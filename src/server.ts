import "dotenv/config";

import express, {
  type NextFunction,
  type Request,
  type Response,
} from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import argon2 from "argon2";
import { Pool, type QueryResultRow } from "pg";
import { WebSocket, WebSocketServer } from "ws";
import { createServer } from "node:http";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { z } from "zod";

const isProd = process.env.NODE_ENV === "production";
const PORT = Number(process.env.PORT ?? 3000);
const SESSION_SECRET = process.env.SESSION_SECRET ?? "";
const DATABASE_URL = process.env.DATABASE_URL ?? "";
const GIPHY_API_KEY = (process.env.GIPHY_API_KEY ?? "").trim();

if (SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET must be at least 32 characters.");
}

if (!DATABASE_URL) {
  throw new Error("DATABASE_URL is required.");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 10,
  ssl: isProd ? { rejectUnauthorized: true } : undefined,
});

pool.on("error", (error) => {
  console.error("PostgreSQL pool error:", error);
});

const PgSession = connectPgSimple(session);

const app = express();
const httpServer = createServer(app);
const publicDir = join(process.cwd(), "public");

/* -------------------------------------------------------------------------- */
/* Security / middleware                                                      */
/* -------------------------------------------------------------------------- */

app.disable("x-powered-by");
app.set("trust proxy", isProd ? 1 : 0);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: [
          "'self'",
          "data:",
          "blob:",
          "https://giphy.com",
          "https://*.giphy.com",
        ],
        mediaSrc: ["'self'", "data:", "blob:"],
        connectSrc: [
          "'self'",
          "https://giphy.com",
          "https://*.giphy.com",
        ],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
      },
    },
  }),
);

app.use(express.json({ limit: "32kb" }));

/*
 * Static assets are intentionally served before the PostgreSQL-backed
 * session middleware so CSS/JS/favicon requests still work if the database
 * has a temporary problem.
 */
app.use(express.static(publicDir));

const sessionMiddleware = session({
  name: "sy.sid",

  secret: SESSION_SECRET,

  resave: false,

  saveUninitialized: false,

  store: new PgSession({
    pool,
    tableName: "user_sessions",
    createTableIfMissing: true,
  }),

  cookie: {
    httpOnly: true,
    secure: isProd,
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 24 * 7,
  },
});

app.use(sessionMiddleware);

declare module "express-session" {
  interface SessionData {
    userId?: number;
    username?: string;
    csrf?: string;
  }
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});

const adminLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});

/* -------------------------------------------------------------------------- */
/* Validation / helpers                                                       */
/* -------------------------------------------------------------------------- */

const usernameSchema = z
  .string()
  .trim()
  .regex(/^[A-Za-z0-9_]+(?: [A-Za-z0-9_]+)?$/)
  .min(4)
  .max(20);

const passwordSchema = z
  .string()
  .min(8)
  .max(128);

const roomSchema = z
  .string()
  .trim()
  .regex(/^[A-Za-z0-9_-]+$/)
  .min(1)
  .max(64);

const messageSchema = z
  .string()
  .trim()
  .min(1)
  .max(2000);

const notificationSchema = z
  .string()
  .trim()
  .min(1)
  .max(2000);

async function query<T extends QueryResultRow = QueryResultRow>(
  text: string,
  values: unknown[] = [],
) {
  return pool.query<T>(text, values);
}

function hashTicket(ticket: string) {
  return createHash("sha256")
    .update(ticket)
    .digest("hex");
}

function safeEqual(a: string, b: string) {
  if (!a || !b || a.length !== b.length) {
    return false;
  }

  return timingSafeEqual(
    Buffer.from(a),
    Buffer.from(b),
  );
}

function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  if (!req.session.userId) {
    return res
      .status(401)
      .json({
        error: "Authentication required.",
      });
  }

  next();
}

async function requireAdmin(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const userId = req.session.userId;

  if (!userId) {
    return res
      .status(401)
      .json({
        error: "Authentication required.",
      });
  }

  try {
    const result = await query<{
      is_admin: boolean;
    }>(
      "SELECT is_admin FROM users WHERE id=$1",
      [userId],
    );

    if (!result.rows[0]?.is_admin) {
      return res
        .status(403)
        .json({
          error: "Admin access required.",
        });
    }

    next();
  } catch (error) {
    next(error);
  }
}

function requireCsrf(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const expected =
    req.session.csrf ?? "";

  const received =
    req.get("x-csrf-token") ?? "";

  if (!safeEqual(expected, received)) {
    return res
      .status(403)
      .json({
        error: "Invalid CSRF token.",
      });
  }

  next();
}

function parsePositiveId(
  value: unknown,
): number | null {
  const raw = Array.isArray(value)
    ? value[0]
    : value;

  if (typeof raw !== "string") {
    return null;
  }

  const id = Number(raw);

  return Number.isSafeInteger(id) && id > 0
    ? id
    : null;
}

async function getUserBan(
  userId: number,
) {
  const result =
    await query<{
      banned_until: string | null;
    }>(
      "SELECT banned_until FROM users WHERE id=$1",
      [userId],
    );

  const raw =
    result.rows[0]?.banned_until ??
    null;

  if (!raw) {
    return null;
  }

  const date = new Date(raw);

  if (
    Number.isNaN(date.getTime()) ||
    date.getTime() <= Date.now()
  ) {
    return null;
  }

  return date.toISOString();
}

async function notifyUser(
  userId: number,
  text: string,
) {
  const result =
    await query<{
      id: number;
      text: string;
      created_at: string;
    }>(
      `INSERT INTO notifications
         (user_id,text)
       VALUES
         ($1,$2)
       RETURNING
         id,text,created_at`,
      [userId, text],
    );

  return result.rows[0] ?? null;
}

/* -------------------------------------------------------------------------- */
/* Database bootstrap                                                         */
/* -------------------------------------------------------------------------- */

async function ensureDatabaseSchema() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(20) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      banned_until TIMESTAMPTZ NULL
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS rooms (
      id SERIAL PRIMARY KEY,
      name VARCHAR(64) UNIQUE NOT NULL,
      owner_id INTEGER NULL
        REFERENCES users(id)
        ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS room_members (
      room_id INTEGER NOT NULL
        REFERENCES rooms(id)
        ON DELETE CASCADE,

      user_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

      PRIMARY KEY (room_id, user_id)
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS room_bans (
      room_id INTEGER NOT NULL
        REFERENCES rooms(id)
        ON DELETE CASCADE,

      user_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

      PRIMARY KEY (room_id, user_id)
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,

      room_id INTEGER NOT NULL
        REFERENCES rooms(id)
        ON DELETE CASCADE,

      user_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      text TEXT NOT NULL,

      metadata JSONB NOT NULL
        DEFAULT '{}'::jsonb,

      created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,

      user_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      text TEXT NOT NULL,

      created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS reports (
      id SERIAL PRIMARY KEY,

      room_id INTEGER NOT NULL
        REFERENCES rooms(id)
        ON DELETE CASCADE,

      reporter_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      reported_username VARCHAR(20) NOT NULL,

      message_text TEXT NOT NULL
        DEFAULT '',

      reason TEXT NOT NULL,

      status VARCHAR(20) NOT NULL
        DEFAULT 'open',

      created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS ws_tickets (
      ticket_hash CHAR(64) PRIMARY KEY,

      user_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      expires_at TIMESTAMPTZ NOT NULL
    )
  `);

  const upgrades = [
    `
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS
      is_admin BOOLEAN NOT NULL DEFAULT FALSE
    `,

    `
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    `,

    `
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS
      banned_until TIMESTAMPTZ NULL
    `,

    `
      ALTER TABLE rooms
      ADD COLUMN IF NOT EXISTS
      owner_id INTEGER NULL
    `,

    `
      ALTER TABLE rooms
      ADD COLUMN IF NOT EXISTS
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    `,

    `
      ALTER TABLE room_members
      ADD COLUMN IF NOT EXISTS
      joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    `,

    `
      ALTER TABLE room_bans
      ADD COLUMN IF NOT EXISTS
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    `,

    `
      ALTER TABLE messages
      ADD COLUMN IF NOT EXISTS
      metadata JSONB NOT NULL
      DEFAULT '{}'::jsonb
    `,

    `
      ALTER TABLE messages
      ADD COLUMN IF NOT EXISTS
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    `,

    `
      ALTER TABLE notifications
      ADD COLUMN IF NOT EXISTS
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    `,

    `
      ALTER TABLE reports
      ADD COLUMN IF NOT EXISTS
      reported_username VARCHAR(20)
      NOT NULL DEFAULT ''
    `,

    `
      ALTER TABLE reports
      ADD COLUMN IF NOT EXISTS
      message_text TEXT
      NOT NULL DEFAULT ''
    `,

    `
      ALTER TABLE reports
      ADD COLUMN IF NOT EXISTS
      reason TEXT
      NOT NULL DEFAULT ''
    `,

    `
      ALTER TABLE reports
      ADD COLUMN IF NOT EXISTS
      status VARCHAR(20)
      NOT NULL DEFAULT 'open'
    `,

    `
      ALTER TABLE reports
      ADD COLUMN IF NOT EXISTS
      created_at TIMESTAMPTZ
      NOT NULL DEFAULT NOW()
    `,
  ];

  upgrades.push(
    `
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS
      avatar_data BYTEA NULL
    `,

    `
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS
      avatar_mime VARCHAR(32) NULL
    `,

    `
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS
      avatar_updated_at TIMESTAMPTZ NULL
    `,

    `
      ALTER TABLE room_bans
      ADD COLUMN IF NOT EXISTS
      expires_at TIMESTAMPTZ NULL
    `,

    `
      ALTER TABLE room_bans
      ADD COLUMN IF NOT EXISTS
      banned_by INTEGER NULL
        REFERENCES users(id)
        ON DELETE SET NULL
    `,

    `
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS
      birth_date DATE NULL
    `,
  );

  for (const sql of upgrades) {
    await query(sql);
  }

  await query(`
    UPDATE rooms r
    SET owner_id = m.user_id
    FROM (
      SELECT DISTINCT ON (room_id)
        room_id,
        user_id
      FROM room_members
      ORDER BY
        room_id,
        joined_at ASC,
        user_id ASC
    ) m
    WHERE
      r.id = m.room_id
      AND r.owner_id IS NULL
  `);

  console.log(
    `GIPHY proxy: ${
      GIPHY_API_KEY
        ? "configured"
        : "not configured"
    }`,
  );
}

/* -------------------------------------------------------------------------- */
/* Authentication                                                             */
/* -------------------------------------------------------------------------- */

app.get(
  "/api/csrf",
  (req, res) => {
    if (!req.session.csrf) {
      req.session.csrf =
        randomBytes(32).toString("hex");
    }

    res.json({
      csrfToken: req.session.csrf,
      token: req.session.csrf,
    });
  },
);

app.post(
  "/api/auth/register",
  authLimiter,
  async (req, res) => {
    const parsed =
      z.object({
        username: usernameSchema,
        password: passwordSchema,
      }).safeParse(req.body);

    if (!parsed.success) {
      return res
        .status(400)
        .json({
          error:
            "Invalid username or password.",
        });
    }

    try {
      const passwordHash =
        await argon2.hash(
          parsed.data.password,
          {
            type: argon2.argon2id,
            memoryCost: 19456,
            timeCost: 2,
            parallelism: 1,
          },
        );

      const isAdmin =
        process.env.ADMIN_USERNAME ===
        parsed.data.username;

      const result =
        await query<{
          id: number;
          username: string;
          is_admin: boolean;
        }>(
          `INSERT INTO users
             (username,password_hash,is_admin)
           VALUES
             ($1,$2,$3)
           RETURNING
             id,username,is_admin`,
          [
            parsed.data.username,
            passwordHash,
            isAdmin,
          ],
        );

      const user =
        result.rows[0];

      if (!user) {
        return res
          .status(500)
          .json({
            error:
              "Could not create account.",
          });
      }

      req.session.regenerate(
        (error) => {
          if (error) {
            return res
              .status(500)
              .json({
                error:
                  "Could not start session.",
              });
          }

          req.session.userId =
            user.id;

          req.session.username =
            user.username;

          req.session.csrf =
            randomBytes(32)
              .toString("hex");

          return res
            .status(201)
            .json({
              username:
                user.username,

              isAdmin:
                user.is_admin,

              csrfToken:
                req.session.csrf,
            });
        },
      );
    } catch (error: unknown) {
      if (
        (error as { code?: string })
          ?.code === "23505"
      ) {
        return res
          .status(409)
          .json({
            error:
              "That username is already taken.",
          });
      }

      console.error(error);

      return res
        .status(500)
        .json({
          error:
            "Registration failed.",
        });
    }
  },
);

app.post(
  "/api/auth/login",
  authLimiter,
  async (req, res) => {
    const parsed =
      z.object({
        username: usernameSchema,
        password: passwordSchema,
      }).safeParse(req.body);

    if (!parsed.success) {
      return res
        .status(400)
        .json({
          error:
            "Invalid credentials.",
        });
    }

    try {
      const result =
        await query<{
          id: number;
          username: string;
          password_hash: string;
          is_admin: boolean;
          banned_until: string | null;
        }>(
          `
          SELECT
            id,
            username,
            password_hash,
            is_admin,
            banned_until
          FROM users
          WHERE username=$1
          `,
          [parsed.data.username],
        );

      const user =
        result.rows[0];

      if (!user) {
        return res
          .status(401)
          .json({
            error:
              "Invalid username or password.",
          });
      }

      const passwordOk =
        await argon2.verify(
          user.password_hash,
          parsed.data.password,
        );

      if (!passwordOk) {
        return res
          .status(401)
          .json({
            error:
              "Invalid username or password.",
          });
      }

      if (
        user.banned_until &&
        new Date(
          user.banned_until,
        ).getTime() > Date.now()
      ) {
        return res
          .status(403)
          .json({
            error:
              `This account is banned until ${
                new Date(
                  user.banned_until,
                ).toLocaleString()
              }.`,
            bannedUntil:
              new Date(
                user.banned_until,
              ).toISOString(),
          });
      }

      /*
       * Keep the current CSRF value across session regeneration so the
       * current chat_app.js can immediately continue with the room request.
       */
      const csrfForNewSession =
        req.session.csrf ||
        randomBytes(32)
          .toString("hex");

      req.session.regenerate(
        (error) => {
          if (error) {
            return res
              .status(500)
              .json({
                error:
                  "Could not start session.",
              });
          }

          req.session.userId =
            user.id;

          req.session.username =
            user.username;

          req.session.csrf =
            csrfForNewSession;

          return res.json({
            username:
              user.username,

            isAdmin:
              user.is_admin,

            csrfToken:
              req.session.csrf,
          });
        },
      );
    } catch (error) {
      console.error(error);

      return res
        .status(500)
        .json({
          error:
            "Login failed.",
        });
    }
  },
);

app.post(
  "/api/auth/logout",
  requireAuth,
  requireCsrf,
  (req, res, next) => {
    req.session.destroy(
      (error) => {
        if (error) {
          return next(error);
        }

        res.clearCookie("sy.sid");
        res.status(204).end();
      },
    );
  },
);

app.get(
  "/api/me",
  requireAuth,
  async (req, res) => {
    const result =
      await query<{
        id: number;
        username: string;
        is_admin: boolean;
        banned_until: string | null;
      }>(
        `
        SELECT
          id,
          username,
          is_admin,
          banned_until
        FROM users
        WHERE id=$1
        `,
        [req.session.userId],
      );

    const user =
      result.rows[0];

    if (!user) {
      return res
        .status(401)
        .json({
          error:
            "Session expired.",
        });
    }

    const bannedUntil =
      user.banned_until &&
      new Date(
        user.banned_until,
      ).getTime() > Date.now()
        ? new Date(
            user.banned_until,
          ).toISOString()
        : null;

    res.json({
      authenticated: true,

      username:
        user.username,

      isAdmin:
        user.is_admin,

      bannedUntil,

      banned:
        Boolean(bannedUntil),

      banMessage:
        bannedUntil
          ? `This account is banned until ${
              new Date(
                bannedUntil,
              ).toLocaleString()
            }.`
          : undefined,
    });
  },
);

app.post(
  "/api/profile/password",
  requireAuth,
  requireCsrf,
  async (req, res) => {
    const parsed =
      z.object({
        currentPassword:
          z.string().min(1),

        newPassword:
          passwordSchema,
      }).safeParse(req.body);

    if (!parsed.success) {
      return res
        .status(400)
        .json({
          error:
            "Invalid password data.",
        });
    }

    const result =
      await query<{
        password_hash: string;
      }>(
        `
        SELECT password_hash
        FROM users
        WHERE id=$1
        `,
        [req.session.userId],
      );

    const user =
      result.rows[0];

    if (
      !user ||
      !(
        await argon2.verify(
          user.password_hash,
          parsed.data.currentPassword,
        )
      )
    ) {
      return res
        .status(400)
        .json({
          error:
            "Current password is incorrect.",
        });
    }

    const passwordHash =
      await argon2.hash(
        parsed.data.newPassword,
        {
          type:
            argon2.argon2id,

          memoryCost:
            19456,

          timeCost:
            2,

          parallelism:
            1,
        },
      );

    await query(
      `
      UPDATE users
      SET password_hash=$1
      WHERE id=$2
      `,
      [
        passwordHash,
        req.session.userId,
      ],
    );

    res.json({
      ok: true,
    });
  },
);

/* -------------------------------------------------------------------------- */
/* Avatars                                                                    */
/* -------------------------------------------------------------------------- */

const AVATAR_MAX_BYTES = 512 * 1024;

const avatarLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});

const avatarBodyParser = express.raw({
  type: ["image/png", "image/jpeg", "image/gif", "image/webp"],
  limit: AVATAR_MAX_BYTES,
});

function parseAvatarBody(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  avatarBodyParser(req, res, (error?: unknown) => {
    if (error) {
      const status =
        (error as { status?: number }).status === 413
          ? 413
          : 400;

      return res.status(status).json({
        error:
          status === 413
            ? "Image is too large (max 512 KB)."
            : "Invalid image upload.",
      });
    }

    next();
  });
}

function detectImageMime(buffer: Buffer): string | null {
  if (
    buffer.length >= 8 &&
    buffer
      .subarray(0, 8)
      .equals(
        Buffer.from([
          0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
        ]),
      )
  ) {
    return "image/png";
  }

  if (
    buffer.length >= 3 &&
    buffer[0] === 0xff &&
    buffer[1] === 0xd8 &&
    buffer[2] === 0xff
  ) {
    return "image/jpeg";
  }

  if (buffer.length >= 6) {
    const head = buffer.subarray(0, 6).toString("ascii");

    if (head === "GIF87a" || head === "GIF89a") {
      return "image/gif";
    }
  }

  if (
    buffer.length >= 12 &&
    buffer.subarray(0, 4).toString("ascii") === "RIFF" &&
    buffer.subarray(8, 12).toString("ascii") === "WEBP"
  ) {
    return "image/webp";
  }

  return null;
}

app.put(
  "/api/profile/avatar",
  requireAuth,
  requireCsrf,
  avatarLimiter,
  parseAvatarBody,
  async (req, res) => {
    const body: unknown = req.body;

    if (!Buffer.isBuffer(body) || body.length === 0) {
      return res.status(400).json({
        error: "Send the image as the request body.",
      });
    }

    const mime = detectImageMime(body);

    if (!mime || mime !== req.get("content-type")?.split(";")[0]) {
      return res.status(400).json({
        error: "Unsupported image. Use PNG, JPEG, WebP or GIF.",
      });
    }

    const result = await query<{
      avatar_updated_at: Date;
    }>(
      `
      UPDATE users
      SET
        avatar_data=$1,
        avatar_mime=$2,
        avatar_updated_at=NOW()
      WHERE id=$3
      RETURNING avatar_updated_at
      `,
      [body, mime, req.session.userId],
    );

    res.json({
      ok: true,
      updatedAt: result.rows[0]?.avatar_updated_at ?? null,
    });
  },
);

app.delete(
  "/api/profile/avatar",
  requireAuth,
  requireCsrf,
  avatarLimiter,
  async (req, res) => {
    await query(
      `
      UPDATE users
      SET
        avatar_data=NULL,
        avatar_mime=NULL,
        avatar_updated_at=NULL
      WHERE id=$1
      `,
      [req.session.userId],
    );

    res.status(204).end();
  },
);

app.get(
  "/api/avatars/:username",
  requireAuth,
  async (req, res) => {
    const parsed = usernameSchema.safeParse(req.params.username);

    if (!parsed.success) {
      return res.status(400).json({
        error: "Invalid username.",
      });
    }

    const result = await query<{
      avatar_data: Buffer | null;
      avatar_mime: string | null;
      avatar_updated_at: Date | null;
    }>(
      `
      SELECT
        avatar_data,
        avatar_mime,
        avatar_updated_at
      FROM users
      WHERE username=$1
      `,
      [parsed.data],
    );

    const row = result.rows[0];

    if (!row?.avatar_data || !row.avatar_mime) {
      return res.status(404).json({
        error: "No avatar.",
      });
    }

    const etag = `W/"${row.avatar_updated_at?.getTime() ?? 0}"`;

    res.setHeader("ETag", etag);
    res.setHeader("Cache-Control", "private, max-age=300");

    if (req.get("if-none-match") === etag) {
      return res.status(304).end();
    }

    res.type(row.avatar_mime).send(row.avatar_data);
  },
);

/* -------------------------------------------------------------------------- */
/* Rooms                                                                      */
/* -------------------------------------------------------------------------- */

app.post(
  "/api/rooms/join",
  requireAuth,
  requireCsrf,
  async (req, res) => {
    const parsed =
      z.object({
        name: roomSchema,
      }).safeParse(req.body);

    if (!parsed.success) {
      return res
        .status(400)
        .json({
          error:
            "Invalid room name.",
        });
    }

    const userId =
      req.session.userId;

    if (!userId) {
      return res
        .status(401)
        .json({
          error:
            "Authentication required.",
        });
    }

    const globalBan =
      await getUserBan(userId);

    if (globalBan) {
      return res
        .status(403)
        .json({
          error:
            `This account is banned until ${
              new Date(
                globalBan,
              ).toLocaleString()
            }.`,
          bannedUntil:
            globalBan,
        });
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        "BEGIN",
      );

      await client.query(
        `
        INSERT INTO rooms
          (name,owner_id)
        VALUES
          ($1,$2)
        ON CONFLICT(name)
        DO NOTHING
        `,
        [
          parsed.data.name,
          userId,
        ],
      );

      const roomResult =
        await client.query<{
          id: number;
          name: string;
          owner_id: number | null;
        }>(
          `
          SELECT
            id,
            name,
            owner_id
          FROM rooms
          WHERE name=$1
          FOR UPDATE
          `,
          [parsed.data.name],
        );

      const room =
        roomResult.rows[0];

      if (!room) {
        await client.query(
          "ROLLBACK",
        );

        return res
          .status(404)
          .json({
            error:
              "Room could not be created.",
          });
      }

      const roomBan =
        await client.query(
          `
          SELECT 1
          FROM room_bans
          WHERE
            room_id=$1
            AND user_id=$2
            AND (expires_at IS NULL OR expires_at > NOW())
          `,
          [
            room.id,
            userId,
          ],
        );

      if (roomBan.rowCount) {
        await client.query(
          "ROLLBACK",
        );

        return res
          .status(403)
          .json({
            error:
              "You are banned from this room.",
          });
      }

      await client.query(
        `
        INSERT INTO room_members
          (room_id,user_id)
        SELECT
          $1,$2
        WHERE NOT EXISTS (
          SELECT 1
          FROM room_members
          WHERE
            room_id=$1
            AND user_id=$2
        )
        `,
        [
          room.id,
          userId,
        ],
      );

      await client.query(
        "COMMIT",
      );

      const isOwner = room.owner_id === userId;

      res.json({
        ...room,
        isAdmin: isOwner,
        canManage: isOwner,
      });
    } catch (error) {
      await client.query(
        "ROLLBACK",
      ).catch(
        () => undefined,
      );

      console.error(error);

      res
        .status(500)
        .json({
          error:
            "Could not join room.",
        });
    } finally {
      client.release();
    }
  },
);

app.get(
  "/api/rooms/:name/members",
  requireAuth,
  async (req, res) => {
    const parsed =
      roomSchema.safeParse(
        req.params.name,
      );

    if (!parsed.success) {
      return res
        .status(400)
        .json({
          error:
            "Invalid room.",
        });
    }

    const userId =
      req.session.userId;

    if (!userId) {
      return res
        .status(401)
        .json({
          error:
            "Authentication required.",
        });
    }

    const membership =
      await query(
        `
        SELECT 1
        FROM room_members rm
        JOIN rooms r
          ON r.id=rm.room_id
        WHERE
          r.name=$1
          AND rm.user_id=$2
        LIMIT 1
        `,
        [
          parsed.data,
          userId,
        ],
      );

    if (!membership.rowCount) {
      return res
        .status(403)
        .json({
          error:
            "You are not a member of this room.",
        });
    }

    const result =
      await query<{
        username: string;
        isAdmin: boolean;
      }>(
        `
        SELECT
          u.username,
          u.is_admin AS "isAdmin"
        FROM room_members rm
        JOIN rooms r
          ON r.id=rm.room_id
        JOIN users u
          ON u.id=rm.user_id
        WHERE r.name=$1
        ORDER BY u.username ASC
        `,
        [parsed.data],
      );

    res.json({
      members:
        result.rows,
    });
  },
);

app.get(
  "/api/rooms/:name/messages",
  requireAuth,
  async (req, res) => {
    const parsed =
      roomSchema.safeParse(
        req.params.name,
      );

    if (!parsed.success) {
      return res
        .status(400)
        .json({
          error:
            "Invalid room.",
        });
    }

    const userId =
      req.session.userId;

    if (!userId) {
      return res
        .status(401)
        .json({
          error:
            "Authentication required.",
        });
    }

    const result =
      await query<{
        id: number;
        username: string;
        text: string;
        metadata: unknown;
        created_at: string;
    is_admin: boolean;
      }>(
        `
        SELECT
          m.id,
          u.username,
          m.text,
          m.metadata,
          m.created_at,
        COALESCE(r.owner_id = u.id, FALSE) AS is_admin
        FROM messages m
        JOIN users u
          ON u.id=m.user_id
        JOIN rooms r
          ON r.id=m.room_id
        JOIN room_members rm
          ON rm.room_id=r.id
          AND rm.user_id=$2
        WHERE r.name=$1
        ORDER BY
          m.created_at ASC,
          m.id ASC
        LIMIT 100
        `,
        [
          parsed.data,
          userId,
        ],
      );

    res.json({
      messages:
        result.rows,
    });
  },
);

/* -------------------------------------------------------------------------- */
/* Notifications                                                              */
/* -------------------------------------------------------------------------- */

app.get(
  "/api/notifications",
  requireAuth,
  async (req, res) => {
    const result =
      await query(
        `
        SELECT
          id,
          text,
          created_at
        FROM notifications
        WHERE user_id=$1
        ORDER BY
          created_at DESC,
          id DESC
        LIMIT 100
        `,
        [req.session.userId],
      );

    res.json({
      notifications:
        result.rows,
    });
  },
);

app.post(
  "/api/notifications",
  requireAuth,
  requireCsrf,
  async (req, res) => {
    const parsed =
      z.object({
        text:
          notificationSchema,
      }).safeParse(
        req.body,
      );

    if (!parsed.success) {
      return res
        .status(400)
        .json({
          error:
            "Invalid notification.",
        });
    }

    const notification =
      await notifyUser(
        req.session.userId!,
        parsed.data.text,
      );

    res
      .status(201)
      .json({
        notification,
      });
  },
);

app.delete(
  "/api/notifications/:id",
  requireAuth,
  requireCsrf,
  async (req, res) => {
    const id =
      parsePositiveId(
        req.params.id,
      );

    if (!id) {
      return res
        .status(400)
        .json({
          error:
            "Invalid notification id.",
        });
    }

    await query(
      `
      DELETE FROM notifications
      WHERE
        id=$1
        AND user_id=$2
      `,
      [
        id,
        req.session.userId,
      ],
    );

    res
      .status(204)
      .end();
  },
);

/* -------------------------------------------------------------------------- */
/* Reports                                                                    */
/* -------------------------------------------------------------------------- */

async function createReport(
  req: Request,
  res: Response,
) {
  const parsed =
    z.object({
      room:
        roomSchema,

      reported_user:
        usernameSchema
          .optional(),

      reportedUsername:
        usernameSchema
          .optional(),

      message_text:
        z.string()
          .max(2000)
          .default(""),

      reason:
        z.string()
          .trim()
          .min(1)
          .max(1000),
    }).safeParse(
      req.body,
    );

  if (!parsed.success) {
    return res
      .status(400)
      .json({
        error:
          "Invalid report.",
      });
  }

  const reportedUser =
    parsed.data.reported_user ??
    parsed.data.reportedUsername;

  if (!reportedUser) {
    return res
      .status(400)
      .json({
        error:
          "Reported username is required.",
      });
  }

  const room =
    await query<{
      id: number;
      owner_id: number | null;
    }>(
      "SELECT id, owner_id FROM rooms WHERE name=$1",
      [parsed.data.room],
    );

  if (!room.rows[0]) {
    return res
      .status(404)
      .json({
        error:
          "Room not found.",
      });
  }

  const membership =
    await query(
      `
      SELECT 1
      FROM room_members
      WHERE
        room_id=$1
        AND user_id=$2
      `,
      [
        room.rows[0].id,
        req.session.userId,
      ],
    );

  if (!membership.rowCount) {
    return res
      .status(403)
      .json({
        error:
          "Join the room first.",
      });
  }

  const messageText =
    parsed.data.message_text ||
    String(
      req.body?.messageText ??
      "",
    );

  const result =
    await query(
      `
      INSERT INTO reports
        (
          room_id,
          reporter_id,
          reported_username,
          message_text,
          reason,
          status
        )
      VALUES
        (
          $1,
          $2,
          $3,
          $4,
          $5,
          'open'
        )
      RETURNING
        id,
        room_id,
        reporter_id,
        reported_username,
        message_text,
        reason,
        status,
        created_at
      `,
      [
        room.rows[0].id,
        req.session.userId,
        reportedUser,
        messageText,
        parsed.data.reason,
      ],
    );

  /* Reports are private: only the room owner hears about them. */
  const reportPayload = {
    type: "new_report",
    room: parsed.data.room,
    report: result.rows[0],
  };

  const managerIds = new Set<number>();

  if (room.rows[0].owner_id !== null) {
    managerIds.add(room.rows[0].owner_id);
  }


  for (const managerId of managerIds) {
    broadcastUser(
      managerId,
      reportPayload,
    );
  }

  res
    .status(201)
    .json({
      report:
        result.rows[0],
    });
}

app.post(
  "/api/reports",
  requireAuth,
  requireCsrf,
  createReport,
);

app.post(
  "/api/rooms/:name/reports",
  requireAuth,
  requireCsrf,
  async (req, res) => {
    req.body = {
      ...req.body,

      room:
        req.params.name,

      reported_user:
        req.body?.reported_user ??
        req.body?.reportedUsername,

      message_text:
        req.body?.message_text ??
        req.body?.messageText ??
        "",
    };

    return createReport(
      req,
      res,
    );
  },
);

/* -------------------------------------------------------------------------- */
/* Admin                                                                      */
/* -------------------------------------------------------------------------- */

app.get(
  "/api/admin/users",
  requireAuth,
  requireAdmin,
  adminLimiter,
  async (_req, res) => {
    const result =
      await query(
        `
        SELECT
          id,
          username,
          is_admin,
          created_at,
          banned_until
        FROM users
        ORDER BY username ASC
        `,
      );

    res.json({
      users:
        result.rows,
    });
  },
);

/*
 * Compatibility endpoint used by the current chat_app.js.
 */
app.post(
  "/api/admin/ban",
  requireAuth,
  requireAdmin,
  requireCsrf,
  adminLimiter,
  async (req, res) => {
    const parsed =
      z.object({
        username:
          usernameSchema,

        days:
          z.coerce
            .number()
            .int()
            .min(1)
            .max(30)
            .default(7),
      }).safeParse(
        req.body ?? {},
      );

    if (!parsed.success) {
      return res
        .status(400)
        .json({
          error:
            "Invalid ban request.",
        });
    }

    if (
      parsed.data.username ===
      req.session.username
    ) {
      return res
        .status(400)
        .json({
          error:
            "You cannot ban yourself.",
        });
    }

    const target =
      await query<{
        id: number;
        username: string;
      }>(
        `
        SELECT
          id,
          username
        FROM users
        WHERE username=$1
        `,
        [
          parsed.data.username,
        ],
      );

    if (!target.rows[0]) {
      return res
        .status(404)
        .json({
          error:
            "User not found.",
        });
    }

    const until =
      new Date(
        Date.now() +
        parsed.data.days *
        24 *
        60 *
        60 *
        1000,
      );

    await query(
      `
      UPDATE users
      SET banned_until=$1
      WHERE id=$2
      `,
      [
        until.toISOString(),
        target.rows[0].id,
      ],
    );

    const text =
      `SY Banned you. You would be off in ${
        parsed.data.days
      } day${
        parsed.data.days === 1
          ? ""
          : "s"
      }.`;

    await notifyUser(
      target.rows[0].id,
      text,
    );

    broadcastUser(
      target.rows[0].id,
      {
        type:
          "notification",

        text,
      },
    );

    broadcastUser(
      target.rows[0].id,
      {
        type:
          "banned",

        until:
          until.toISOString(),
      },
    );

    res.json({
      ok: true,

      username:
        target.rows[0].username,

      bannedUntil:
        until.toISOString(),
    });
  },
);

app.post(
  "/api/admin/users/:username/ban",
  requireAuth,
  requireAdmin,
  requireCsrf,
  adminLimiter,
  async (req, res) => {
    const username =
      usernameSchema.safeParse(
        req.params.username,
      );

    if (!username.success) {
      return res
        .status(400)
        .json({
          error:
            "Invalid username.",
        });
    }

    if (
      username.data ===
      req.session.username
    ) {
      return res
        .status(400)
        .json({
          error:
            "You cannot ban yourself.",
        });
    }

    const parsed =
      z.object({
        days:
          z.coerce
            .number()
            .int()
            .min(1)
            .max(30)
            .default(7),
      }).safeParse(
        req.body ?? {},
      );

    if (!parsed.success) {
      return res
        .status(400)
        .json({
          error:
            "Invalid ban duration.",
        });
    }

    const target =
      await query<{
        id: number;
        username: string;
      }>(
        `
        SELECT
          id,
          username
        FROM users
        WHERE username=$1
        `,
        [
          username.data,
        ],
      );

    if (!target.rows[0]) {
      return res
        .status(404)
        .json({
          error:
            "User not found.",
        });
    }

    const until =
      new Date(
        Date.now() +
        parsed.data.days *
        24 *
        60 *
        60 *
        1000,
      );

    await query(
      `
      UPDATE users
      SET banned_until=$1
      WHERE id=$2
      `,
      [
        until.toISOString(),
        target.rows[0].id,
      ],
    );

    const text =
      `SY Banned you. You would be off in ${
        parsed.data.days
      } day${
        parsed.data.days === 1
          ? ""
          : "s"
      }.`;

    await notifyUser(
      target.rows[0].id,
      text,
    );

    broadcastUser(
      target.rows[0].id,
      {
        type:
          "notification",

        text,
      },
    );

    broadcastUser(
      target.rows[0].id,
      {
        type:
          "banned",

        until:
          until.toISOString(),
      },
    );

    res.json({
      ok: true,

      ban: {
        username:
          target.rows[0].username,

        bannedUntil:
          until.toISOString(),

        expiresAt:
          until.toISOString(),
      },
    });
  },
);

app.post(
  "/api/admin/users/:username/unban",
  requireAuth,
  requireAdmin,
  requireCsrf,
  adminLimiter,
  async (req, res) => {
    const username =
      usernameSchema.safeParse(
        req.params.username,
      );

    if (!username.success) {
      return res
        .status(400)
        .json({
          error:
            "Invalid username.",
        });
    }

    const target =
      await query<{
        id: number;
        username: string;
      }>(
        `
        SELECT
          id,
          username
        FROM users
        WHERE username=$1
        `,
        [
          username.data,
        ],
      );

    if (!target.rows[0]) {
      return res
        .status(404)
        .json({
          error:
            "User not found.",
        });
    }

    await query(
      `
      UPDATE users
      SET banned_until=NULL
      WHERE id=$1
      `,
      [
        target.rows[0].id,
      ],
    );

    broadcastUser(
      target.rows[0].id,
      {
        type:
          "notification",

        text:
          "Your ban has been cancelled.",
      },
    );

    res.json({
      ok: true,
    });
  },
);

app.delete(
  "/api/admin/rooms/:room",
  requireAuth,
  requireAdmin,
  requireCsrf,
  adminLimiter,
  async (req, res) => {
    const parsed =
      roomSchema.safeParse(
        req.params.room,
      );

    if (!parsed.success) {
      return res
        .status(400)
        .json({
          error:
            "Invalid room.",
        });
    }

    const room =
      await query<{
        id: number;
      }>(
        `
        SELECT id
        FROM rooms
        WHERE name=$1
        `,
        [parsed.data],
      );

    if (!room.rows[0]) {
      return res
        .status(404)
        .json({
          error:
            "Room not found.",
        });
    }

    const clients =
      clientsByRoom.get(
        parsed.data,
      );

    broadcast(
      parsed.data,
      {
        type:
          "room_deleted",

        text:
          `#${parsed.data} was deleted by the admin.`,
      },
    );

    await query(
      "DELETE FROM messages WHERE room_id=$1",
      [room.rows[0].id],
    );

    await query(
      "DELETE FROM reports WHERE room_id=$1",
      [room.rows[0].id],
    );

    await query(
      "DELETE FROM room_bans WHERE room_id=$1",
      [room.rows[0].id],
    );

    await query(
      "DELETE FROM room_members WHERE room_id=$1",
      [room.rows[0].id],
    );

    await query(
      "DELETE FROM rooms WHERE id=$1",
      [room.rows[0].id],
    );

    if (clients) {
      for (const ws of clients) {
        try {
          ws.close(
            1000,
            "Room deleted",
          );
        } catch (_) {}
      }

      clientsByRoom.delete(
        parsed.data,
      );
    }

    res
      .status(204)
      .end();
  },
);

app.get(
  "/api/admin/reports",
  requireAuth,
  requireAdmin,
  adminLimiter,
  async (_req, res) => {
    const result =
      await query(
        `
        SELECT
          rp.id,
          rp.reported_username,
          rp.reported_username
            AS reported_user,
          reporter.username
            AS reporter,
          r.name AS room,
          rp.message_text,
          rp.reason,
          rp.status,
          rp.created_at
        FROM reports rp

        JOIN users reporter
          ON reporter.id=rp.reporter_id

        JOIN rooms r
          ON r.id=rp.room_id

        ORDER BY
          rp.created_at DESC,
          rp.id DESC
        `,
      );

    res.json({
      reports:
        result.rows,
    });
  },
);

app.post(
  "/api/admin/reports/:id/dismiss",
  requireAuth,
  requireAdmin,
  requireCsrf,
  adminLimiter,
  async (req, res) => {
    const id =
      parsePositiveId(
        req.params.id,
      );

    if (!id) {
      return res
        .status(400)
        .json({
          error:
            "Invalid report id.",
        });
    }

    const result =
      await query<{
        reporter_id: number;
        status: string;
      }>(
        `
        UPDATE reports
        SET status='dismissed'
        WHERE id=$1
        RETURNING
          reporter_id,
          status
        `,
        [id],
      );

    const report =
      result.rows[0];

    if (!report) {
      return res
        .status(404)
        .json({
          error:
            "Report not found.",
        });
    }

    const text =
      "Your report is not accepted";

    await notifyUser(
      report.reporter_id,
      text,
    );

    broadcastUser(
      report.reporter_id,
      {
        type:
          "notification",

        text,
      },
    );

    res.json({
      ok: true,

      status:
        report.status,
    });
  },
);

/* -------------------------------------------------------------------------- */
/* GIPHY proxy                                                                */
/* -------------------------------------------------------------------------- */

async function proxyGiphy(
  kind:
    | "trending"
    | "search",

  req: Request,

  res: Response,
) {
  if (!GIPHY_API_KEY) {
    return res
      .status(503)
      .json({
        error:
          "GIPHY is not configured on the server.",
      });
  }

  const limit =
    Math.min(
      24,
      Math.max(
        1,
        Number(
          req.query.limit,
        ) || 24,
      ),
    );

  const params =
    new URLSearchParams({
      api_key:
        GIPHY_API_KEY,

      limit:
        String(limit),

      rating:
        "g",

      bundle:
        "messaging_non_clips",

      lang:
        "en",
    });

  if (kind === "search") {
    const q =
      String(
        req.query.q ?? "",
      )
        .trim()
        .slice(0, 50);

    if (!q) {
      return res
        .status(400)
        .json({
          error:
            "Search query is required.",
        });
    }

    params.set(
      "q",
      q,
    );
  }

  try {
    const response =
      await fetch(
        `https://api.giphy.com/v1/gifs/${kind}?${params.toString()}`,
      );

    const body =
      await response
        .json()
        .catch(
          () => ({}),
        );

    return res
      .status(response.status)
      .json(body);
  } catch (error) {
    console.error(
      "GIPHY proxy error:",
      error,
    );

    return res
      .status(502)
      .json({
        error:
          "Could not reach GIPHY.",
      });
  }
}

app.get(
  "/api/gifs/trending",
  requireAuth,
  async (req, res) =>
    proxyGiphy(
      "trending",
      req,
      res,
    ),
);

app.get(
  "/api/gifs/search",
  requireAuth,
  async (req, res) =>
    proxyGiphy(
      "search",
      req,
      res,
    ),
);

/* -------------------------------------------------------------------------- */
/* Birth date (Events tab)                                                    */
/* -------------------------------------------------------------------------- */

const birthdateLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});

app.get(
  "/api/profile/birthdate",
  requireAuth,
  async (req, res) => {
    const result = await query<{
      birth_date: string | null;
    }>(
      `
      SELECT to_char(birth_date, 'YYYY-MM-DD') AS birth_date
      FROM users
      WHERE id=$1
      `,
      [req.session.userId],
    );

    res.json({
      birthDate: result.rows[0]?.birth_date ?? null,
    });
  },
);

app.put(
  "/api/profile/birthdate",
  requireAuth,
  requireCsrf,
  birthdateLimiter,
  async (req, res) => {
    const parsed = z
      .object({
        birthDate: z
          .string()
          .regex(/^\d{4}-\d{2}-\d{2}$/),
      })
      .safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "Enter a valid birth date.",
      });
    }

    const parts = parsed.data.birthDate.split("-");
    const year = Number(parts[0]);
    const month = Number(parts[1]);
    const day = Number(parts[2]);

    const date = new Date(
      Date.UTC(year, month - 1, day),
    );

    const valid =
      date.getUTCFullYear() === year &&
      date.getUTCMonth() === month - 1 &&
      date.getUTCDate() === day;

    if (
      !valid ||
      year < 1900 ||
      date.getTime() > Date.now() + 24 * 60 * 60 * 1000
    ) {
      return res.status(400).json({
        error: "Enter a valid birth date.",
      });
    }

    await query(
      "UPDATE users SET birth_date=$1::date WHERE id=$2",
      [parsed.data.birthDate, req.session.userId],
    );

    res.json({
      ok: true,
      birthDate: parsed.data.birthDate,
    });
  },
);

/* -------------------------------------------------------------------------- */
/* Room administration (room owner only)                                      */
/* -------------------------------------------------------------------------- */

type ManagedRoom = {
  id: number;
  name: string;
  owner_id: number | null;
  isOwner: boolean;
};

async function loadManagedRoom(
  req: Request,
  res: Response,
): Promise<ManagedRoom | null> {
  const parsed = roomSchema.safeParse(
    req.params.name,
  );

  if (!parsed.success) {
    res.status(400).json({
      error: "Invalid room.",
    });

    return null;
  }

  const roomResult = await query<{
    id: number;
    name: string;
    owner_id: number | null;
  }>(
    "SELECT id, name, owner_id FROM rooms WHERE name=$1",
    [parsed.data],
  );

  const room = roomResult.rows[0];

  if (!room) {
    res.status(404).json({
      error: "Room not found.",
    });

    return null;
  }

  const isOwner =
    room.owner_id !== null &&
    room.owner_id === req.session.userId;

  if (!isOwner) {
    res.status(403).json({
      error: "Only the room admin can do this.",
    });

    return null;
  }

  return { ...room, isOwner };
}

app.get(
  "/api/rooms/:name/manage",
  requireAuth,
  adminLimiter,
  async (req, res) => {
    const room = await loadManagedRoom(req, res);

    if (!room) {
      return;
    }

    const members = await query(
      `
      SELECT
        u.username,
        (r.owner_id = u.id) AS "isOwner",
        u.is_admin AS "isAdmin"
      FROM room_members m
      JOIN users u ON u.id = m.user_id
      JOIN rooms r ON r.id = m.room_id
      WHERE m.room_id = $1
      ORDER BY
        (r.owner_id = u.id) DESC,
        u.username ASC
      `,
      [room.id],
    );

    const bans = await query(
      `
      SELECT
        u.username,
        b.expires_at AS "expiresAt",
        b.created_at AS "createdAt"
      FROM room_bans b
      JOIN users u ON u.id = b.user_id
      WHERE
        b.room_id = $1
        AND (
          b.expires_at IS NULL
          OR b.expires_at > NOW()
        )
      ORDER BY b.created_at DESC
      `,
      [room.id],
    );

    const reports = await query(
      `
      SELECT
        rp.id,
        rp.reported_username AS reported_user,
        reporter.username AS reporter,
        rp.message_text,
        rp.reason,
        rp.status,
        rp.created_at
      FROM reports rp
      JOIN users reporter
        ON reporter.id = rp.reporter_id
      WHERE rp.room_id = $1
      ORDER BY
        rp.created_at DESC,
        rp.id DESC
      LIMIT 100
      `,
      [room.id],
    );

    res.json({
      room: room.name,
      isOwner: room.isOwner,
      members: members.rows,
      bans: bans.rows,
      reports: reports.rows,
    });
  },
);

app.post(
  "/api/rooms/:name/bans",
  requireAuth,
  requireCsrf,
  adminLimiter,
  async (req, res) => {
    const room = await loadManagedRoom(req, res);

    if (!room) {
      return;
    }

    const parsed = z
      .object({
        username: usernameSchema,
        days: z
          .union([
            z.null(),
            z.coerce
              .number()
              .int()
              .min(1)
              .max(365),
          ])
          .optional(),
      })
      .safeParse(req.body ?? {});

    if (!parsed.success) {
      return res.status(400).json({
        error: "Invalid ban request.",
      });
    }

    if (parsed.data.username === req.session.username) {
      return res.status(400).json({
        error: "You cannot ban yourself.",
      });
    }

    const target = await query<{
      id: number;
      username: string;
      is_admin: boolean;
    }>(
      "SELECT id, username, is_admin FROM users WHERE username=$1",
      [parsed.data.username],
    );

    const user = target.rows[0];

    if (!user) {
      return res.status(404).json({
        error: "User not found.",
      });
    }

    if (user.id === room.owner_id) {
      return res.status(403).json({
        error: "You cannot ban the room owner.",
      });
    }

    if (user.is_admin) {
      return res.status(403).json({
        error: "You cannot ban an administrator.",
      });
    }

    const days = parsed.data.days ?? null;

    const expires =
      days === null
        ? null
        : new Date(
            Date.now() + days * 24 * 60 * 60 * 1000,
          );

    await query(
      `
      INSERT INTO room_bans
        (room_id, user_id, banned_by, expires_at)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (room_id, user_id)
      DO UPDATE SET
        banned_by = EXCLUDED.banned_by,
        expires_at = EXCLUDED.expires_at,
        created_at = NOW()
      `,
      [
        room.id,
        user.id,
        req.session.userId,
        expires ? expires.toISOString() : null,
      ],
    );

    await query(
      "DELETE FROM room_members WHERE room_id=$1 AND user_id=$2",
      [room.id, user.id],
    );

    const text =
      days === null
        ? `You were permanently banned from #${room.name}.`
        : `You were banned from #${room.name} for ${days} day${days === 1 ? "" : "s"}.`;

    await notifyUser(user.id, text);

    broadcastUser(user.id, {
      type: "notification",
      text,
    });

    const clients = clientsByRoom.get(room.name);

    if (clients) {
      for (const ws of [...clients]) {
        if (ws.userId !== user.id) {
          continue;
        }

        try {
          ws.send(
            JSON.stringify({
              type: "kicked",
              room: room.name,
              text,
              until: expires
                ? expires.toISOString()
                : null,
            }),
          );

          ws.close(1000, "Banned from room");
        } catch (_) {
          /* socket already closed */
        }

        clients.delete(ws);
      }
    }

    res.json({
      ok: true,
      username: user.username,
      expiresAt: expires
        ? expires.toISOString()
        : null,
    });
  },
);

app.delete(
  "/api/rooms/:name/bans/:username",
  requireAuth,
  requireCsrf,
  adminLimiter,
  async (req, res) => {
    const room = await loadManagedRoom(req, res);

    if (!room) {
      return;
    }

    const username = usernameSchema.safeParse(
      req.params.username,
    );

    if (!username.success) {
      return res.status(400).json({
        error: "Invalid username.",
      });
    }

    const result = await query<{
      user_id: number;
    }>(
      `
      DELETE FROM room_bans
      WHERE
        room_id = $1
        AND user_id = (
          SELECT id FROM users WHERE username = $2
        )
      RETURNING user_id
      `,
      [room.id, username.data],
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: "This user is not banned from the room.",
      });
    }

    const text = `You can join #${room.name} again.`;

    await notifyUser(result.rows[0].user_id, text);

    broadcastUser(result.rows[0].user_id, {
      type: "notification",
      text,
    });

    res.status(204).end();
  },
);

async function resolveRoomReport(
  req: Request,
  res: Response,
  status: "dismissed" | "accepted",
) {
  const room = await loadManagedRoom(req, res);

  if (!room) {
    return;
  }

  const id = parsePositiveId(req.params.id);

  if (!id) {
    return res.status(400).json({
      error: "Invalid report id.",
    });
  }

  const result = await query<{
    reporter_id: number;
  }>(
    `
    UPDATE reports
    SET status = $3
    WHERE id = $1 AND room_id = $2
    RETURNING reporter_id
    `,
    [id, room.id, status],
  );

  const report = result.rows[0];

  if (!report) {
    return res.status(404).json({
      error: "Report not found.",
    });
  }

  const text =
    status === "accepted"
      ? "Your report was accepted."
      : "Your report is not accepted";

  await notifyUser(report.reporter_id, text);

  broadcastUser(report.reporter_id, {
    type: "notification",
    text,
  });

  res.json({
    ok: true,
    status,
  });
}

app.post(
  "/api/rooms/:name/reports/:id/dismiss",
  requireAuth,
  requireCsrf,
  adminLimiter,
  (req, res) =>
    resolveRoomReport(req, res, "dismissed"),
);

app.post(
  "/api/rooms/:name/reports/:id/accept",
  requireAuth,
  requireCsrf,
  adminLimiter,
  (req, res) =>
    resolveRoomReport(req, res, "accepted"),
);

app.delete(
  "/api/rooms/:name",
  requireAuth,
  requireCsrf,
  adminLimiter,
  async (req, res) => {
    const room = await loadManagedRoom(req, res);

    if (!room) {
      return;
    }

    broadcast(room.name, {
      type: "room_deleted",
      text: `#${room.name} was deleted by its admin.`,
    });

    await query("DELETE FROM messages WHERE room_id=$1", [room.id]);
    await query("DELETE FROM reports WHERE room_id=$1", [room.id]);
    await query("DELETE FROM room_bans WHERE room_id=$1", [room.id]);
    await query("DELETE FROM room_members WHERE room_id=$1", [room.id]);
    await query("DELETE FROM rooms WHERE id=$1", [room.id]);

    const clients = clientsByRoom.get(room.name);

    if (clients) {
      for (const ws of clients) {
        try {
          ws.close(1000, "Room deleted");
        } catch (_) {
          /* socket already closed */
        }
      }

      clientsByRoom.delete(room.name);
    }

    res.status(204).end();
  },
);

/* -------------------------------------------------------------------------- */
/* WebSocket                                                                  */
/* -------------------------------------------------------------------------- */

type ChatWebSocket =
  WebSocket & {
    userId?: number;
    username?: string;
    room?: string;
  };

const clientsByRoom =
  new Map<
    string,
    Set<ChatWebSocket>
  >();

const clientsByUser =
  new Map<
    number,
    Set<ChatWebSocket>
  >();

function broadcast(
  room: string,
  payload: unknown,
  except?: WebSocket,
) {
  const clients =
    clientsByRoom.get(
      room,
    );

  if (!clients) {
    return;
  }

  const text =
    JSON.stringify(
      payload,
    );

  for (const ws of clients) {
    if (
      ws !== except &&
      ws.readyState ===
        WebSocket.OPEN
    ) {
      ws.send(text);
    }
  }
}

function addUserSocket(
  ws: ChatWebSocket,
) {
  if (!ws.userId) {
    return;
  }

  let clients =
    clientsByUser.get(
      ws.userId,
    );

  if (!clients) {
    clients =
      new Set<ChatWebSocket>();

    clientsByUser.set(
      ws.userId,
      clients,
    );
  }

  clients.add(ws);
}

function removeUserSocket(
  ws: ChatWebSocket,
) {
  if (!ws.userId) {
    return;
  }

  const clients =
    clientsByUser.get(
      ws.userId,
    );

  if (!clients) {
    return;
  }

  clients.delete(ws);

  if (clients.size === 0) {
    clientsByUser.delete(
      ws.userId,
    );
  }
}

function broadcastUser(
  userId: number,
  payload: unknown,
) {
  const clients =
    clientsByUser.get(
      userId,
    );

  if (!clients) {
    return;
  }

  const text =
    JSON.stringify(
      payload,
    );

  for (const ws of clients) {
    if (
      ws.readyState ===
      WebSocket.OPEN
    ) {
      ws.send(text);
    }
  }
}

app.post(
  "/api/ws-ticket",
  requireAuth,
  requireCsrf,
  async (req, res) => {
    const userId =
      req.session.userId;

    if (!userId) {
      return res
        .status(401)
        .json({
          error:
            "Authentication required.",
        });
    }

    const bannedUntil =
      await getUserBan(
        userId,
      );

    if (bannedUntil) {
      return res
        .status(403)
        .json({
          error:
            `This account is banned until ${
              new Date(
                bannedUntil,
              ).toLocaleString()
            }.`,
          bannedUntil,
        });
    }

    await query(
      `
      DELETE FROM ws_tickets
      WHERE expires_at < NOW()
      `,
      [],
    );

    const ticket =
      randomBytes(32)
        .toString("base64url");

    await query(
      `
      INSERT INTO ws_tickets
        (
          ticket_hash,
          user_id,
          expires_at
        )
      VALUES
        (
          $1,
          $2,
          NOW() + INTERVAL '60 seconds'
        )
      `,
      [
        hashTicket(ticket),
        userId,
      ],
    );

    res.json({
      ticket,
    });
  },
);

const wss =
  new WebSocketServer({
    noServer: true,
  });

httpServer.on(
  "upgrade",
  (
    req,
    socket,
    head,
  ) => {
    try {
      const url =
        new URL(
          req.url ?? "/",
          "http://localhost",
        );

      if (
        url.pathname !==
        "/ws"
      ) {
        socket.destroy();
        return;
      }

      const ticket =
        url.searchParams.get(
          "ticket",
        ) ?? "";

      if (
        !ticket ||
        ticket.length > 200
      ) {
        socket.destroy();
        return;
      }

      const ticketHash =
        hashTicket(ticket);

      query<{
        user_id: number;
        username: string;
      }>(
        `
        DELETE FROM ws_tickets t
        USING users u

        WHERE
          t.ticket_hash=$1
          AND t.user_id=u.id
          AND t.expires_at>NOW()

        RETURNING
          t.user_id,
          u.username
        `,
        [ticketHash],
      )
        .then(
          (
            result,
          ) => {
            const row =
              result.rows[0];

            if (!row) {
              socket.destroy();
              return;
            }

            wss.handleUpgrade(
              req,
              socket,
              head,
              (ws) => {
                const secureSocket =
                  ws as ChatWebSocket;

                secureSocket.userId =
                  row.user_id;

                secureSocket.username =
                  row.username;

                addUserSocket(
                  secureSocket,
                );

                wss.emit(
                  "connection",
                  secureSocket,
                );
              },
            );
          },
        )
        .catch(
          () => {
            socket.destroy();
          },
        );
    } catch {
      socket.destroy();
    }
  },
);

wss.on(
  "connection",
  (
    ws: ChatWebSocket,
  ) => {
    ws.on(
      "message",
      async (raw) => {
        try {
          const payload =
            JSON.parse(
              raw.toString(),
            ) as {
              type?: string;
              room?: string;
              text?: string;
              metadata?: unknown;
            };

          /* ---------------------------------------------------------------- */
          /* JOIN                                                             */
          /* ---------------------------------------------------------------- */

          if (
            payload.type ===
            "join"
          ) {
            if (!ws.userId) {
              ws.send(
                JSON.stringify({
                  type:
                    "error",

                  error:
                    "Authentication required.",
                }),
              );

              return;
            }

            const roomResult =
              roomSchema.safeParse(
                payload.room ??
                  "",
              );

            if (!roomResult.success) {
              ws.send(
                JSON.stringify({
                  type:
                    "error",

                  error:
                    "Invalid room name.",
                }),
              );

              return;
            }

            const room =
              roomResult.data;

            const membership =
              await query(
                `
                SELECT 1
                FROM room_members rm

                JOIN rooms r
                  ON r.id=rm.room_id

                WHERE
                  r.name=$1
                  AND rm.user_id=$2

                LIMIT 1
                `,
                [
                  room,
                  ws.userId,
                ],
              );

            if (
              !membership.rowCount
            ) {
              ws.send(
                JSON.stringify({
                  type:
                    "error",

                  error:
                    "Join the room first.",
                }),
              );

              return;
            }

            if (
              ws.room
            ) {
              const oldClients =
                clientsByRoom.get(
                  ws.room,
                );

              oldClients?.delete(
                ws,
              );

              if (
                oldClients &&
                oldClients.size === 0
              ) {
                clientsByRoom.delete(
                  ws.room,
                );
              }
            }

            ws.room =
              room;

            let clients =
              clientsByRoom.get(
                room,
              );

            if (!clients) {
              clients =
                new Set<ChatWebSocket>();

              clientsByRoom.set(
                room,
                clients,
              );
            }

            clients.add(ws);

            ws.send(
              JSON.stringify({
                type:
                  "joined",

                room,
              }),
            );

            return;
          }

          /* ---------------------------------------------------------------- */
          /* MESSAGE                                                          */
          /* ---------------------------------------------------------------- */

          if (
            payload.type ===
            "message"
          ) {
            if (!ws.userId) {
              ws.send(
                JSON.stringify({
                  type:
                    "error",

                  error:
                    "Authentication required.",
                }),
              );

              return;
            }

            if (!ws.room) {
              ws.send(
                JSON.stringify({
                  type:
                    "error",

                  error:
                    "Join a room first.",
                }),
              );

              return;
            }

            /*
             * Normal text messages must contain text, but media messages
             * (GIF/image/video/audio) may carry their content in metadata.
             *
             * The previous messageSchema.parse() rejected media messages
             * when text was empty and produced the ZodError in the server
             * console. We now allow an empty text field when metadata exists.
             */
            const textResult = z
              .string()
              .trim()
              .max(2000)
              .safeParse(
                payload.text ??
                  "",
              );

            if (!textResult.success) {
              ws.send(
                JSON.stringify({
                  type:
                    "error",

                  error:
                    "Message is too long.",
                }),
              );

              return;
            }

            const text =
              textResult.data;

            const metadata =
              payload.metadata &&
              typeof payload.metadata ===
                "object" &&
              !Array.isArray(
                payload.metadata,
              )
                ? payload.metadata
                : {};

            const hasMetadata =
              Object.keys(
                metadata,
              ).length > 0;

            /*
             * Reject a completely empty message.
             * Media messages are allowed because their content
             * is stored in metadata.
             */
            if (
              !text &&
              !hasMetadata
            ) {
              ws.send(
                JSON.stringify({
                  type:
                    "error",

                  error:
                    "Message cannot be blank.",
                }),
              );

              return;
            }

            const result =
              await query<{
                id: number;
                username: string;
                text: string;
                metadata: unknown;
                created_at: string;
    is_admin: boolean;
              }>(
                `
                INSERT INTO messages
                  (
                    room_id,
                    user_id,
                    text,
                    metadata
                  )

                SELECT
                  id,
                  $2,
                  $3,
                  $4::jsonb

                FROM rooms

                WHERE name=$1

                RETURNING
                  id,

                  (
                    SELECT username
                    FROM users
                    WHERE id=$2
                  ) AS username,

                  text,
                  metadata,
                  created_at,
      COALESCE((
        SELECT r.owner_id = $2
        FROM rooms r
        WHERE r.id = messages.room_id
      ), FALSE) AS is_admin
                `,
                [
                  ws.room,
                  ws.userId,
                  text,
                  JSON.stringify(
                    metadata,
                  ),
                ],
              );

            const message =
              result.rows[0];

            if (!message) {
              ws.send(
                JSON.stringify({
                  type:
                    "error",

                  error:
                    "Could not save message.",
                }),
              );

              return;
            }

            const payloadOut = {
              type:
                "message",

              message,
            };

            broadcast(
              ws.room,
              payloadOut,
              ws,
            );

            ws.send(
              JSON.stringify(
                payloadOut,
              ),
            );

            return;
          }
        } catch (error) {
          console.error(
            "WebSocket message error:",
            error,
          );

          ws.send(
            JSON.stringify({
              type:
                "error",

              error:
                "Invalid message.",
            }),
          );
        }
      },
    );

    ws.on(
      "close",
      () => {
        if (ws.room) {
          const clients =
            clientsByRoom.get(
              ws.room,
            );

          clients?.delete(ws);

          if (
            clients &&
            clients.size === 0
          ) {
            clientsByRoom.delete(
              ws.room,
            );
          }
        }

        removeUserSocket(
          ws,
        );
      },
    );
  },
);

/* -------------------------------------------------------------------------- */
/* API 404 + errors                                                           */
/* -------------------------------------------------------------------------- */

app.use(
  "/api",
  (_req, res) => {
    res
      .status(404)
      .json({
        error:
          "API endpoint not found.",
      });
  },
);

app.use(
  (
    err: unknown,
    _req: Request,
    res: Response,
    _next: NextFunction,
  ) => {
    console.error(err);

    if (!res.headersSent) {
      res
        .status(500)
        .json({
          error:
            "Internal server error.",
        });
    }
  },
);

/* -------------------------------------------------------------------------- */
/* Start                                                                      */
/* -------------------------------------------------------------------------- */

async function start() {
  await ensureDatabaseSchema();

  await pool.query(
    "SELECT 1",
  );

  httpServer.listen(
    PORT,
    () => {
      console.log(
        `SY Chat Web secure server listening on http://localhost:${PORT}`,
      );
    },
  );
}

start().catch(
  (error) => {
    console.error(
      "SY Chat Web failed to start:",
      error,
    );

    process.exit(1);
  },
);