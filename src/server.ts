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
/* Render sets PORT (default 10000). Locally we fall back to 3000. */
const PORT = Number(process.env.PORT) || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET ?? "";
const DATABASE_URL = process.env.DATABASE_URL ?? "";
const GIPHY_API_KEY = (process.env.GIPHY_API_KEY ?? "").trim();

if (SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET must be at least 32 characters.");
}

if (!DATABASE_URL) {
  throw new Error("DATABASE_URL is required.");
}

/*
 * Database SSL (DATABASE_SSL):
 *   unset / "auto" -> SSL only for Render's EXTERNAL url (host ends with
 *                     .render.com). Render's INTERNAL url needs no SSL.
 *   "false"        -> never use SSL
 *   "require"      -> SSL without certificate verification
 *   "verify"       -> SSL with full certificate verification
 */
function databaseSsl(): false | { rejectUnauthorized: boolean } {
  const mode = (process.env.DATABASE_SSL ?? "auto").trim().toLowerCase();

  if (["false", "off", "disable", "0", "no"].includes(mode)) {
    return false;
  }

  if (mode === "verify") {
    return { rejectUnauthorized: true };
  }

  if (["true", "on", "require", "1", "yes"].includes(mode)) {
    return { rejectUnauthorized: false };
  }

  try {
    if (new URL(DATABASE_URL).hostname.endsWith(".render.com")) {
      return { rejectUnauthorized: false };
    }
  } catch (_) {
    /* not a URL: let pg report the problem */
  }

  return false;
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 10,
  ssl: databaseSsl(),
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
/*
 * LiveKit (video meetings). Create a project at https://cloud.livekit.io (or
 * self-host LiveKit) and set these three values in .env:
 *   LIVEKIT_URL=wss://your-project.livekit.cloud
 *   LIVEKIT_API_KEY=...
 *   LIVEKIT_API_SECRET=...
 */
const livekitUrl = (process.env.LIVEKIT_URL ?? "").trim();
const livekitApiKey = (process.env.LIVEKIT_API_KEY ?? "").trim();
const livekitApiSecret = (process.env.LIVEKIT_API_SECRET ?? "").trim();

const livekitConfigured = Boolean(
  livekitUrl && livekitApiKey && livekitApiSecret,
);

function livekitHttpUrl() {
  return livekitUrl
    .replace(/^wss:/i, "https:")
    .replace(/^ws:/i, "http:");
}

/* The browser must be allowed to open the LiveKit signalling connection. */
const livekitConnectSources: string[] = [];

/* Explicit wss:// for this site (Render sets RENDER_EXTERNAL_HOSTNAME; use PUBLIC_HOSTNAME for a custom domain). */
const publicHostname = (
  process.env.PUBLIC_HOSTNAME ??
  process.env.RENDER_EXTERNAL_HOSTNAME ??
  ""
).trim();

const publicConnectSources = publicHostname
  ? [`https://${publicHostname}`, `wss://${publicHostname}`]
  : [];

if (livekitConfigured) {
  try {
    const host = new URL(livekitHttpUrl()).host;

    livekitConnectSources.push(
      `https://${host}`,
      `wss://${host}`,
      `http://${host}`,
      `ws://${host}`,
    );
  } catch (_) {
    console.warn("[meeting] LIVEKIT_URL is not a valid URL.");
  }
}

/*
 * Behind Render's proxies. TRUST_PROXY = number of proxy hops in front of the
 * app (default 1 in production). If every visitor seems to share one IP (the
 * rate limit hits everybody at once), raise it and check the result at
 * /api/admin/client-ip while logged in as an admin.
 */
const trustProxyHops = Number(process.env.TRUST_PROXY ?? (isProd ? 1 : 0));

app.set(
  "trust proxy",
  Number.isInteger(trustProxyHops) && trustProxyHops >= 0
    ? trustProxyHops
    : 1,
);

/* Render health check: no session, no database, answers instantly. */
app.get("/healthz", (_req, res) => {
  res.status(200).type("text/plain").send("ok");
});

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
          ...publicConnectSources,
          ...livekitConnectSources,
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

/* Images that no notification uses any more (and are older than 1 hour). */
async function cleanupOrphanNotificationImages() {
  await query(
    `
    DELETE FROM notification_images i
    WHERE
      i.created_at < NOW() - INTERVAL '1 hour'
      AND NOT EXISTS (
        SELECT 1 FROM notifications n
        WHERE n.image_id = i.id
      )
    `,
  );
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

    `
      CREATE TABLE IF NOT EXISTS notification_images (
        id SERIAL PRIMARY KEY,
        mime VARCHAR(32) NOT NULL,
        data BYTEA NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `,

    `
      ALTER TABLE notifications
      ADD COLUMN IF NOT EXISTS
      image_id INTEGER NULL
        REFERENCES notification_images(id)
        ON DELETE SET NULL
    `,

    `
      CREATE TABLE IF NOT EXISTS chat_files (
        id SERIAL PRIMARY KEY,
        room_id INTEGER NOT NULL
          REFERENCES rooms(id)
          ON DELETE CASCADE,
        user_id INTEGER NULL
          REFERENCES users(id)
          ON DELETE SET NULL,
        name VARCHAR(200) NOT NULL,
        mime VARCHAR(100) NOT NULL,
        size INTEGER NOT NULL,
        preview TEXT NULL,
        data BYTEA NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
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
        created_at,
        CASE
          WHEN image_id IS NULL THEN NULL
          ELSE '/api/notification-images/' || image_id
        END AS image_url
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

    await cleanupOrphanNotificationImages();

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
        u.id,
        u.username,
        u.is_admin,
        u.created_at,
        u.banned_until,
        (SELECT COUNT(*) FROM messages m WHERE m.user_id = u.id)::int AS message_count,
        (SELECT COUNT(*) FROM rooms r WHERE r.owner_id = u.id)::int AS owned_rooms
      FROM users u
      ORDER BY u.username ASC
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
/* Private admin page (/admin) - global admins only                           */
/* -------------------------------------------------------------------------- */

/*
 * The page and its script live in ./admin (NOT in ./public), so express.static
 * can never serve them. They are only reachable through these gated routes.
 * Not logged in -> back to the login page. Logged in but not an admin -> 404,
 * so the page's existence is not revealed.
 */
const adminDir = join(process.cwd(), "admin");

async function requireAdminPage(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const userId = req.session.userId;

  if (!userId) {
    return res.redirect(302, "/");
  }

  try {
    const result = await query<{
      username: string;
      is_admin: boolean;
    }>(
      "SELECT username, is_admin FROM users WHERE id=$1",
      [userId],
    );

    const user = result.rows[0];

    if (!user?.is_admin) {
      console.warn(
        `[admin] /admin refused: "${user?.username ?? "unknown"}" is not a site admin. ` +
          `To allow it, run: UPDATE users SET is_admin = TRUE WHERE username = '${user?.username ?? ""}';`,
      );

      return res
        .status(404)
        .type("text/plain")
        .send("Not found");
    }

    res.setHeader("Cache-Control", "private, no-store");
    res.setHeader("X-Robots-Tag", "noindex, nofollow");

    next();
  } catch (error) {
    next(error);
  }
}

function sendAdminFile(res: Response, fileName: string) {
  const filePath = join(adminDir, fileName);

  res.sendFile(filePath, (error) => {
    if (!error) {
      return;
    }

    console.error(
      `[admin] could not send ${filePath}: ${error.message}. ` +
        `The "admin" folder must be next to the "public" folder (current directory: ${process.cwd()}).`,
    );

    if (!res.headersSent) {
      res
        .status(500)
        .type("text/plain")
        .send(
          "Admin page files are missing on the server. Put the admin folder next to the public folder.",
        );
    }
  });
}

app.get(
  "/admin",
  requireAdminPage,
  (_req, res) => {
    sendAdminFile(res, "admin.html");
  },
);

app.get(
  "/admin/app.js",
  requireAdminPage,
  (_req, res) => {
    sendAdminFile(res, "admin.js");
  },
);

/* -------------------------------------------------------------------------- */
/* Admin console API (global admins only)                                     */
/* -------------------------------------------------------------------------- */

app.get(
  "/api/admin/stats",
  requireAuth,
  requireAdmin,
  adminLimiter,
  async (_req, res) => {
    const result = await query<{
      users: number;
      admins: number;
      banned_users: number;
      rooms: number;
      messages: number;
      messages_today: number;
      open_reports: number;
    }>(
      `
      SELECT
        (SELECT COUNT(*) FROM users)::int AS users,
        (SELECT COUNT(*) FROM users WHERE is_admin)::int AS admins,
        (
          SELECT COUNT(*) FROM users
          WHERE banned_until IS NOT NULL AND banned_until > NOW()
        )::int AS banned_users,
        (SELECT COUNT(*) FROM rooms)::int AS rooms,
        (SELECT COUNT(*) FROM messages)::int AS messages,
        (
          SELECT COUNT(*) FROM messages
          WHERE created_at > NOW() - INTERVAL '24 hours'
        )::int AS messages_today,
        (SELECT COUNT(*) FROM reports WHERE status = 'open')::int AS open_reports
      `,
    );

    let onlineUsers = 0;

    for (const sockets of clientsByUser.values()) {
      if (sockets.size > 0) {
        onlineUsers += 1;
      }
    }

    res.json({
      ...result.rows[0],
      online_users: onlineUsers,
    });
  },
);

app.get(
  "/api/admin/rooms",
  requireAuth,
  requireAdmin,
  adminLimiter,
  async (_req, res) => {
    const result = await query<{
      id: number;
      name: string;
      created_at: string;
      owner: string | null;
      members: number;
      messages: number;
      open_reports: number;
    }>(
      `
      SELECT
        r.id,
        r.name,
        r.created_at,
        o.username AS owner,
        (SELECT COUNT(*) FROM room_members m WHERE m.room_id = r.id)::int AS members,
        (SELECT COUNT(*) FROM messages x WHERE x.room_id = r.id)::int AS messages,
        (
          SELECT COUNT(*) FROM reports p
          WHERE p.room_id = r.id AND p.status = 'open'
        )::int AS open_reports
      FROM rooms r
      LEFT JOIN users o ON o.id = r.owner_id
      ORDER BY r.created_at DESC
      `,
    );

    res.json({
      rooms: result.rows.map((room) => ({
        ...room,
        online: clientsByRoom.get(room.name)?.size ?? 0,
      })),
    });
  },
);

app.post(
  "/api/admin/reports/:id/accept",
  requireAuth,
  requireAdmin,
  requireCsrf,
  adminLimiter,
  async (req, res) => {
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
      SET status = 'accepted'
      WHERE id = $1
      RETURNING reporter_id
      `,
      [id],
    );

    const report = result.rows[0];

    if (!report) {
      return res.status(404).json({
        error: "Report not found.",
      });
    }

    const text = "Your report was accepted.";

    await notifyUser(report.reporter_id, text);

    broadcastUser(report.reporter_id, {
      type: "notification",
      text,
    });

    res.json({
      ok: true,
      status: "accepted",
    });
  },
);

app.post(
  "/api/admin/users/:username/admin",
  requireAuth,
  requireAdmin,
  requireCsrf,
  adminLimiter,
  async (req, res) => {
    const username = usernameSchema.safeParse(
      req.params.username,
    );

    const body = z
      .object({ isAdmin: z.boolean() })
      .safeParse(req.body ?? {});

    if (!username.success || !body.success) {
      return res.status(400).json({
        error: "Invalid request.",
      });
    }

    if (username.data === req.session.username) {
      return res.status(400).json({
        error: "You cannot change your own admin status.",
      });
    }

    if (
      !body.data.isAdmin &&
      process.env.ADMIN_USERNAME === username.data
    ) {
      return res.status(403).json({
        error: "This is the main administrator account.",
      });
    }

    const result = await query<{
      id: number;
      username: string;
      is_admin: boolean;
    }>(
      `
      UPDATE users
      SET is_admin = $1
      WHERE username = $2
      RETURNING id, username, is_admin
      `,
      [body.data.isAdmin, username.data],
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({
        error: "User not found.",
      });
    }

    const text = body.data.isAdmin
      ? "You are now an administrator."
      : "Your administrator access was removed.";

    await notifyUser(user.id, text);

    broadcastUser(user.id, {
      type: "notification",
      text,
    });

    res.json({
      ok: true,
      username: user.username,
      isAdmin: user.is_admin,
    });
  },
);

/* Helps to check TRUST_PROXY behind a proxy: "ip" must be YOUR public IP. */
app.get(
  "/api/admin/client-ip",
  requireAuth,
  requireAdmin,
  adminLimiter,
  (req, res) => {
    res.json({
      ip: req.ip,
      ips: req.ips,
      xForwardedFor: req.headers["x-forwarded-for"] ?? null,
      trustProxy: app.get("trust proxy"),
      secure: req.secure,
    });
  },
);

/* -------------------------------------------------------------------------- */
/* Admin notifications (text + optional image) and image delivery             */
/* -------------------------------------------------------------------------- */

const NOTIFICATION_IMAGE_MAX_BYTES = 2 * 1024 * 1024;

const notificationImageParser = express.raw({
  type: ["image/png", "image/jpeg", "image/gif", "image/webp"],
  limit: NOTIFICATION_IMAGE_MAX_BYTES,
});

function parseNotificationImageBody(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  notificationImageParser(req, res, (error?: unknown) => {
    if (error) {
      const status =
        (error as { status?: number }).status === 413
          ? 413
          : 400;

      return res.status(status).json({
        error:
          status === 413
            ? "Image is too large (max 2 MB)."
            : "Invalid image upload.",
      });
    }

    next();
  });
}

app.put(
  "/api/admin/notification-images",
  requireAuth,
  requireAdmin,
  requireCsrf,
  adminLimiter,
  parseNotificationImageBody,
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

    await cleanupOrphanNotificationImages();

    const result = await query<{
      id: number;
    }>(
      `
      INSERT INTO notification_images (mime, data)
      VALUES ($1, $2)
      RETURNING id
      `,
      [mime, body],
    );

    const imageId = result.rows[0]?.id;

    res.status(201).json({
      imageId,
      url: `/api/notification-images/${imageId}`,
    });
  },
);

app.post(
  "/api/admin/notifications",
  requireAuth,
  requireAdmin,
  requireCsrf,
  adminLimiter,
  async (req, res) => {
    const parsed = z
      .object({
        text: z.string().trim().min(1).max(1000),
        imageId: z.number().int().positive().nullable().optional(),
        target: z.discriminatedUnion("type", [
          z.object({ type: z.literal("all") }),
          z.object({
            type: z.literal("user"),
            username: usernameSchema,
          }),
          z.object({
            type: z.literal("room"),
            room: roomSchema,
          }),
        ]),
      })
      .safeParse(req.body ?? {});

    if (!parsed.success) {
      return res.status(400).json({
        error: "Write a message (1 to 1000 characters) and choose who receives it.",
      });
    }

    const { text, target } = parsed.data;
    const imageId = parsed.data.imageId ?? null;

    if (imageId !== null) {
      const image = await query(
        "SELECT 1 FROM notification_images WHERE id=$1",
        [imageId],
      );

      if (!image.rowCount) {
        return res.status(400).json({
          error: "The image was not found. Upload it again.",
        });
      }
    }

    let inserted;

    if (target.type === "all") {
      inserted = await query<{ user_id: number }>(
        `
        INSERT INTO notifications (user_id, text, image_id)
        SELECT id, $1::text, $2::integer FROM users
        RETURNING user_id
        `,
        [text, imageId],
      );
    } else if (target.type === "user") {
      inserted = await query<{ user_id: number }>(
        `
        INSERT INTO notifications (user_id, text, image_id)
        SELECT id, $1::text, $2::integer
        FROM users
        WHERE username = $3
        RETURNING user_id
        `,
        [text, imageId, target.username],
      );

      if (!inserted.rows.length) {
        return res.status(404).json({
          error: "User not found.",
        });
      }
    } else {
      const room = await query(
        "SELECT 1 FROM rooms WHERE name=$1",
        [target.room],
      );

      if (!room.rowCount) {
        return res.status(404).json({
          error: "Room not found.",
        });
      }

      inserted = await query<{ user_id: number }>(
        `
        INSERT INTO notifications (user_id, text, image_id)
        SELECT m.user_id, $1::text, $2::integer
        FROM room_members m
        JOIN rooms r ON r.id = m.room_id
        WHERE r.name = $3
        RETURNING user_id
        `,
        [text, imageId, target.room],
      );
    }

    for (const row of inserted.rows) {
      broadcastUser(row.user_id, {
        type: "notification",
        text,
        hasImage: imageId !== null,
      });
    }

    res.status(201).json({
      ok: true,
      recipients: inserted.rows.length,
    });
  },
);

app.get(
  "/api/notification-images/:id",
  requireAuth,
  async (req, res) => {
    const id = parsePositiveId(req.params.id);

    if (!id) {
      return res.status(400).json({
        error: "Invalid image id.",
      });
    }

    const result = await query<{
      mime: string;
      data: Buffer;
    }>(
      `
      SELECT i.mime, i.data
      FROM notification_images i
      WHERE
        i.id = $1
        AND (
          EXISTS (
            SELECT 1 FROM notifications n
            WHERE n.image_id = i.id AND n.user_id = $2
          )
          OR EXISTS (
            SELECT 1 FROM users u
            WHERE u.id = $2 AND u.is_admin
          )
        )
      `,
      [id, req.session.userId],
    );

    const image = result.rows[0];

    if (!image) {
      return res.status(404).json({
        error: "Image not found.",
      });
    }

    res.setHeader(
      "Cache-Control",
      "private, max-age=86400, immutable",
    );

    res.type(image.mime).send(image.data);
  },
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
  "/api/rooms/:name/manage/summary",
  requireAuth,
  adminLimiter,
  async (req, res) => {
    const room = await loadManagedRoom(req, res);

    if (!room) {
      return;
    }

    const result = await query<{
      count: string;
    }>(
      `
      SELECT COUNT(*)::text AS count
      FROM reports
      WHERE room_id = $1 AND status = 'open'
      `,
      [room.id],
    );

    res.json({
      openReports: Number(result.rows[0]?.count ?? 0),
    });
  },
);

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
/* Chat files (upload / preview / download) and meeting configuration        */
/* -------------------------------------------------------------------------- */

const CHAT_FILE_MAX_BYTES = 10 * 1024 * 1024;

const chatFileLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});

const chatFileParser = express.raw({
  type: () => true,
  limit: CHAT_FILE_MAX_BYTES,
});

function parseChatFileBody(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  chatFileParser(req, res, (error?: unknown) => {
    if (error) {
      const status =
        (error as { status?: number }).status === 413
          ? 413
          : 400;

      return res.status(status).json({
        error:
          status === 413
            ? "File is too large (max 10 MB)."
            : "Invalid file upload.",
      });
    }

    next();
  });
}

/* Types that are safe to display inline (never SVG / HTML). */
const SAFE_INLINE_MIME =
  /^(image\/(png|jpeg|gif|webp)|video\/(mp4|webm|ogg|quicktime)|audio\/(mpeg|ogg|wav|webm|mp4|aac)|application\/pdf|text\/plain)$/;

const TEXT_PREVIEW_EXT =
  /\.(txt|md|csv|json|log|js|ts|py|css|xml|yml|yaml|ini|sql|sh)$/i;

function sanitizeFileName(raw: string): string {
  const cleaned = raw
    .replace(/[\\/\u0000-\u001f\u007f"<>|?*:]/g, "_")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/^\.+/, "");

  return (cleaned || "file").slice(0, 120);
}

app.put(
  "/api/rooms/:name/files",
  requireAuth,
  requireCsrf,
  chatFileLimiter,
  parseChatFileBody,
  async (req, res) => {
    const roomName = roomSchema.safeParse(req.params.name);

    if (!roomName.success) {
      return res.status(400).json({
        error: "Invalid room.",
      });
    }

    const membership = await query<{
      id: number;
    }>(
      `
      SELECT r.id
      FROM rooms r
      JOIN room_members m ON m.room_id = r.id
      WHERE r.name = $1 AND m.user_id = $2
      `,
      [roomName.data, req.session.userId],
    );

    const roomId = membership.rows[0]?.id;

    if (!roomId) {
      return res.status(403).json({
        error: "Join the room first.",
      });
    }

    const body: unknown = req.body;

    if (!Buffer.isBuffer(body) || body.length === 0) {
      return res.status(400).json({
        error: "Send the file as the request body.",
      });
    }

    const name = sanitizeFileName(String(req.query.name ?? "file"));
    const declared = String(req.query.type ?? "")
      .split(";")[0]
      .trim()
      .toLowerCase();

    /* The declared type is only trusted when the content matches it. */
    let mime = "application/octet-stream";

    if (declared.startsWith("image/")) {
      if (detectImageMime(body) === declared) {
        mime = declared;
      }
    } else if (declared === "application/pdf") {
      if (body.subarray(0, 5).toString("latin1") === "%PDF-") {
        mime = declared;
      }
    } else if (SAFE_INLINE_MIME.test(declared)) {
      mime = declared;
    }

    let preview: string | null = null;

    if (mime === "text/plain" || TEXT_PREVIEW_EXT.test(name)) {
      const head = body.subarray(0, 2400);

      if (!head.includes(0)) {
        preview = head.toString("utf8").slice(0, 600).trim() || null;
      }
    }

    const result = await query<{
      id: number;
    }>(
      `
      INSERT INTO chat_files
        (room_id, user_id, name, mime, size, preview, data)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id
      `,
      [
        roomId,
        req.session.userId,
        name,
        mime,
        body.length,
        preview,
        body,
      ],
    );

    res.status(201).json({
      fileId: result.rows[0]?.id,
      name,
      mime,
      size: body.length,
      preview,
    });
  },
);

app.get(
  "/api/files/:id",
  requireAuth,
  async (req, res) => {
    const id = parsePositiveId(req.params.id);

    if (!id) {
      return res.status(400).json({
        error: "Invalid file id.",
      });
    }

    const result = await query<{
      name: string;
      mime: string;
      data: Buffer;
    }>(
      `
      SELECT f.name, f.mime, f.data
      FROM chat_files f
      JOIN room_members m
        ON m.room_id = f.room_id AND m.user_id = $2
      WHERE f.id = $1
      `,
      [id, req.session.userId],
    );

    const file = result.rows[0];

    if (!file) {
      return res.status(404).json({
        error: "File not found.",
      });
    }

    const inline =
      req.query.inline === "1" &&
      SAFE_INLINE_MIME.test(file.mime);

    const asciiName = file.name
      .replace(/[^\x20-\x7e]/g, "_")
      .replace(/["\\]/g, "_");

    /*
     * Chrome's built-in PDF viewer can be blocked by the page-wide CSP
     * (object-src 'none'). The file was validated (%PDF- header) and is served
     * with nosniff, so the policy is dropped for inline PDFs only.
     */
    if (inline && file.mime === "application/pdf") {
      res.removeHeader("Content-Security-Policy");
    }

    res.setHeader("Content-Type", file.mime);
    res.setHeader(
      "Content-Disposition",
      `${inline ? "inline" : "attachment"}; filename="${asciiName}"; filename*=UTF-8''${encodeURIComponent(file.name)}`,
    );
    res.setHeader("Accept-Ranges", "bytes");
    res.setHeader("Cache-Control", "private, max-age=3600");

    const total = file.data.length;
    const range = /^bytes=(\d*)-(\d*)$/.exec(
      String(req.headers.range ?? ""),
    );

    if (range && (range[1] !== "" || range[2] !== "")) {
      let start: number;
      let end: number;

      if (range[1] === "") {
        start = Math.max(0, total - Number(range[2]));
        end = total - 1;
      } else {
        start = Number(range[1]);
        end =
          range[2] === ""
            ? total - 1
            : Math.min(Number(range[2]), total - 1);
      }

      if (start >= total || end < start) {
        res.setHeader("Content-Range", `bytes */${total}`);

        return res.status(416).end();
      }

      res.status(206);
      res.setHeader(
        "Content-Range",
        `bytes ${start}-${end}/${total}`,
      );
      res.setHeader("Content-Length", String(end - start + 1));

      return res.end(file.data.subarray(start, end + 1));
    }

    res.setHeader("Content-Length", String(total));

    res.end(file.data);
  },
);

/* -------------------------------------------------------------------------- */
/* Meetings (LiveKit)                                                         */
/* -------------------------------------------------------------------------- */

const meetingLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 240,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});

const MEETING_NOT_CONFIGURED =
  "Meetings are not set up on this server yet. The administrator must set LIVEKIT_URL, LIVEKIT_API_KEY and LIVEKIT_API_SECRET.";

function livekitRoomName(room: string) {
  return `sy-chat-${room}`;
}

/* The caller must be a member of the room (banned users are not). */
async function loadMeetingRoom(
  req: Request,
  res: Response,
): Promise<string | null> {
  const parsed = roomSchema.safeParse(req.params.name);

  if (!parsed.success) {
    res.status(400).json({
      error: "Invalid room.",
    });

    return null;
  }

  const result = await query(
    `
    SELECT 1
    FROM rooms r
    JOIN room_members m ON m.room_id = r.id
    WHERE r.name = $1 AND m.user_id = $2
    `,
    [parsed.data, req.session.userId],
  );

  if (!result.rowCount) {
    res.status(403).json({
      error: "Join the room first.",
    });

    return null;
  }

  return parsed.data;
}

const meetingStatusCache = new Map<
  string,
  { at: number; participants: string[] }
>();

async function meetingParticipants(
  room: string,
): Promise<string[]> {
  const cached = meetingStatusCache.get(room);

  if (cached && Date.now() - cached.at < 4000) {
    return cached.participants;
  }

  let participants: string[] = [];

  try {
    const { RoomServiceClient } = await import(
      "livekit-server-sdk"
    );

    const client = new RoomServiceClient(
      livekitHttpUrl(),
      livekitApiKey,
      livekitApiSecret,
    );

    const list = await client.listParticipants(
      livekitRoomName(room),
    );

    participants = list.map((p) => p.identity);
  } catch (_) {
    /* The LiveKit room does not exist yet: nobody is in the meeting. */
  }

  meetingStatusCache.set(room, {
    at: Date.now(),
    participants,
  });

  return participants;
}

app.get(
  "/api/rooms/:name/meeting",
  requireAuth,
  meetingLimiter,
  async (req, res) => {
    const room = await loadMeetingRoom(req, res);

    if (!room) {
      return;
    }

    if (!livekitConfigured) {
      return res.json({
        configured: false,
        count: 0,
        participants: [],
      });
    }

    const participants = await meetingParticipants(room);

    res.json({
      configured: true,
      count: participants.length,
      participants,
    });
  },
);

app.post(
  "/api/rooms/:name/meeting/token",
  requireAuth,
  requireCsrf,
  meetingLimiter,
  async (req, res) => {
    const room = await loadMeetingRoom(req, res);

    if (!room) {
      return;
    }

    if (!livekitConfigured) {
      return res.status(503).json({
        error: MEETING_NOT_CONFIGURED,
      });
    }

    const username = req.session.username;

    if (!username) {
      return res.status(401).json({
        error: "Please log in again.",
      });
    }

    let token: string;

    try {
      const { AccessToken } = await import(
        "livekit-server-sdk"
      );

      const accessToken = new AccessToken(
        livekitApiKey,
        livekitApiSecret,
        {
          identity: username,
          name: username,
          ttl: "4h",
        },
      );

      accessToken.addGrant({
        roomJoin: true,
        room: livekitRoomName(room),
        canPublish: true,
        canSubscribe: true,
        canPublishData: true,
      });

      token = await accessToken.toJwt();
    } catch (error) {
      console.error(
        "[meeting] could not create a LiveKit token. Is livekit-server-sdk installed?",
        error,
      );

      return res.status(503).json({
        error:
          "The meeting service is not available. The administrator must run: npm install livekit-server-sdk",
      });
    }

    meetingStatusCache.delete(room);

    broadcast(room, {
      type: "meeting_changed",
      room,
    });

    res.json({
      token,
      url: livekitUrl,
    });
  },
);

/* Called after leaving, so the others refresh the Meeting button quickly. */
app.post(
  "/api/rooms/:name/meeting/changed",
  requireAuth,
  requireCsrf,
  meetingLimiter,
  async (req, res) => {
    const room = await loadMeetingRoom(req, res);

    if (!room) {
      return;
    }

    meetingStatusCache.delete(room);

    broadcast(room, {
      type: "meeting_changed",
      room,
    });

    res.status(204).end();
  },
);

/* The LiveKit browser SDK is served from this server (the CSP only allows 'self' scripts). */
app.get(
  "/vendor/livekit-client.umd.js",
  (_req, res) => {
    res.sendFile(
      join(
        process.cwd(),
        "node_modules",
        "livekit-client",
        "dist",
        "livekit-client.umd.js",
      ),
      { maxAge: "1d" },
      (error) => {
        if (error && !res.headersSent) {
          res
            .status(404)
            .type("text/plain")
            .send(
              "livekit-client is not installed. Run: npm install livekit-client",
            );
        }
      },
    );
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

/* -------------------------------------------------------------------------- */
/* WebSocket helpers                                                          */
/* -------------------------------------------------------------------------- */

function sendJson(
  ws: WebSocket,
  payload: unknown,
) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(payload));
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
              to?: number;
              data?: unknown;
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

            /*
             * Link and file messages are rebuilt on the server so a client
             * cannot forge them (javascript: links, other people's files...).
             */
            let safeMetadata: Record<string, unknown> =
              metadata as Record<string, unknown>;

            const metadataKind = safeMetadata.type;

            if (metadataKind === "link") {
              const linkResult = z
                .object({
                  url: z.string().max(2048),
                  label: z.string().trim().max(80).optional(),
                })
                .safeParse(safeMetadata);

              let href: string | null = null;

              if (linkResult.success) {
                try {
                  const parsedUrl = new URL(linkResult.data.url);

                  if (
                    parsedUrl.protocol === "http:" ||
                    parsedUrl.protocol === "https:"
                  ) {
                    href = parsedUrl.href;
                  }
                } catch (_) {
                  href = null;
                }
              }

              if (!href || !linkResult.success) {
                sendJson(ws, {
                  type: "error",
                  error: "Enter a valid http(s) link.",
                });

                return;
              }

              safeMetadata = {
                type: "link",
                url: href,
                label: linkResult.data.label ?? "",
              };
            } else if (metadataKind === "file") {
              const fileId = Number(safeMetadata.fileId);

              const fileRow = Number.isInteger(fileId) && fileId > 0
                ? await query<{
                    name: string;
                    mime: string;
                    size: number;
                    preview: string | null;
                  }>(
                    `
                    SELECT f.name, f.mime, f.size, f.preview
                    FROM chat_files f
                    JOIN rooms r ON r.id = f.room_id
                    WHERE f.id = $1 AND r.name = $2 AND f.user_id = $3
                    `,
                    [fileId, ws.room, ws.userId],
                  )
                : null;

              const file = fileRow?.rows[0];

              if (!file) {
                sendJson(ws, {
                  type: "error",
                  error: "File not found. Upload it again.",
                });

                return;
              }

              safeMetadata = {
                type: "file",
                fileId,
                name: file.name,
                mime: file.mime,
                size: file.size,
                preview: file.preview,
              };
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
                    safeMetadata,
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
/* Keep-alive, health and shutdown (Render)                                   */
/* -------------------------------------------------------------------------- */

/*
 * Proxies close idle connections, and Render recommends server-side pings.
 * Browsers answer ping frames automatically. A socket that did not answer the
 * previous ping is dead and gets terminated (its "close" handler cleans up).
 */
const HEARTBEAT_INTERVAL_MS = 30_000;

type HeartbeatSocket = WebSocket & { isAlive?: boolean };

wss.on("connection", (ws: HeartbeatSocket) => {
  ws.isAlive = true;

  ws.on("pong", () => {
    ws.isAlive = true;
  });
});

const heartbeatTimer = setInterval(() => {
  wss.clients.forEach((client) => {
    const ws = client as HeartbeatSocket;

    if (ws.isAlive === false) {
      ws.terminate();
      return;
    }

    ws.isAlive = false;

    try {
      ws.ping();
    } catch (_) {
      /* socket already closing */
    }
  });
}, HEARTBEAT_INTERVAL_MS);

heartbeatTimer.unref();

/* Render sends SIGTERM on every deploy/restart: close cleanly, clients reconnect. */
let shuttingDown = false;

function shutdown(signal: string) {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;
  console.log(`${signal} received: shutting down gracefully...`);

  clearInterval(heartbeatTimer);

  wss.clients.forEach((client) => {
    try {
      client.close(1001, "Server restarting");
    } catch (_) {
      /* ignore */
    }
  });

  httpServer.close(() => {
    pool
      .end()
      .catch(() => undefined)
      .finally(() => process.exit(0));
  });

  setTimeout(() => process.exit(0), 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

/* -------------------------------------------------------------------------- */
/* Start                                                                      */
/* -------------------------------------------------------------------------- */

async function start() {
  await ensureDatabaseSchema();

  await pool.query(
    "SELECT 1",
  );

  /*
   * Longer than the proxy's idle timeout, so the proxy never reuses a
   * connection that Node already closed (prevents random 502 errors).
   */
  httpServer.keepAliveTimeout = 120_000;
  httpServer.headersTimeout = 125_000;

  httpServer.listen(
    PORT,
    "0.0.0.0",
    () => {
      console.log(
        `SY Chat Web v1.0.0 listening on 0.0.0.0:${PORT} (${isProd ? "production" : "development"})`,
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
