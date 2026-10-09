let authMode = "login";
let csrf = "";
let socket = null;
let currentRoom = "";
let currentUser = "";
let wsTicket = "";

const $ = (id) => document.getElementById(id);

const auth = $("auth");
const room = $("room");
const chat = $("chat");
const authForm = $("authForm");

async function api(url, options = {}) {
    const headers = new Headers(options.headers || {});

    if (options.body) {
        headers.set("content-type", "application/json");
    }

    if (options.method && options.method !== "GET") {
        headers.set("x-csrf-token", csrf);
    }

    const r = await fetch(url, {
        ...options,
        headers,
        credentials: "same-origin"
    });

    const data =
        r.status === 204
            ? undefined
            : await r.json().catch(() => ({}));

    if (!r.ok) {
        throw new Error(data?.error || "Request failed.");
    }

    return data;
}

async function init() {
    try {
        const c = await fetch("/api/csrf", {
            credentials: "same-origin"
        });

        if (!c.ok) {
            throw new Error("Could not initialize security token.");
        }

        const data = await c.json();
        csrf = data.token;

        try {
            const me = await api("/api/me");
            enterRoomSelection(me.username);
        } catch {
            showAuth();
        }
    } catch (error) {
        console.error("Initialization error:", error);
        showAuth();
    }
}

function showAuth() {
    auth.classList.remove("hidden");
    room.classList.add("hidden");
    chat.classList.add("hidden");
}

function enterRoomSelection(username) {
    currentUser = username;

    auth.classList.add("hidden");
    room.classList.remove("hidden");
    chat.classList.add("hidden");

    $("me").textContent = username;
}

$("loginTab").onclick = () => {
    authMode = "login";

    $("loginTab").classList.add("active");
    $("signupTab").classList.remove("active");

    $("authSubmit").textContent = "Login";
};

$("signupTab").onclick = () => {
    authMode = "register";

    $("signupTab").classList.add("active");
    $("loginTab").classList.remove("active");

    $("authSubmit").textContent = "Create account";
};

authForm.onsubmit = async (e) => {
    e.preventDefault();

    $("authError").textContent = "";

    try {
        const data = await api(
            authMode === "login"
                ? "/api/auth/login"
                : "/api/auth/register",
            {
                method: "POST",
                body: JSON.stringify({
                    username: $("username").value,
                    password: $("password").value
                })
            }
        );

        currentUser = data.username;
        enterRoomSelection(currentUser);
    } catch (err) {
        $("authError").textContent =
            err instanceof Error ? err.message : "Request failed.";
    }
};

$("roomForm").onsubmit = async (e) => {
    e.preventDefault();

    $("roomError").textContent = "";

    const name = $("roomName").value.trim();

    try {
        await api("/api/rooms/join", {
            method: "POST",
            body: JSON.stringify({ name })
        });

        await openChat(name);
    } catch (err) {
        $("roomError").textContent =
            err instanceof Error ? err.message : "Could not join room.";
    }
};

async function openChat(name) {
    currentRoom = name;

    room.classList.add("hidden");
    chat.classList.remove("hidden");

    $("chatTitle").textContent = "#" + name;
    $("onlineState").textContent = "Loading…";
    $("messages").innerHTML = "";

    const history = await api(
        `/api/rooms/${encodeURIComponent(name)}/messages`
    );

    if (Array.isArray(history)) {
        history.forEach(renderMessage);
    }

    const ticketResponse = await api("/api/ws-ticket", {
        method: "GET"
    }).catch(() => null);

    if (!ticketResponse?.ticket) {
        throw new Error("Could not create real-time connection ticket.");
    }

    wsTicket = ticketResponse.ticket;

    connectSocket(name);
}

function connectSocket(name) {
    socket?.close();

    socket = new WebSocket(
        `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws?ticket=${encodeURIComponent(wsTicket)}`
    );

    socket.onopen = () => {
        socket.send(
            JSON.stringify({
                type: "join",
                room: name
            })
        );

        $("onlineState").textContent = "Online";
    };

    socket.onclose = () => {
        $("onlineState").textContent = "Offline";
    };

    socket.onerror = (error) => {
        console.error("WebSocket error:", error);
        $("onlineState").textContent = "Offline";
    };

    socket.onmessage = (e) => {
        try {
            const payload = JSON.parse(e.data);

            if (payload.type === "message" && payload.message) {
                renderMessage(payload.message);
            }

            if (payload.type === "error") {
                alert(payload.error || "WebSocket error.");
            }
        } catch (error) {
            console.error("Invalid WebSocket message:", error);
        }
    };
}

function renderMessage(m) {
    const wrap = document.createElement("article");

    wrap.className =
        "msg" + (m.username === currentUser ? " mine" : "");

    const name = document.createElement("div");
    name.className = "name";
    name.textContent = m.username || "";

    const bubble = document.createElement("div");
    bubble.className = "bubble";

    const inner = document.createElement("div");
    inner.textContent = m.text || "";

    bubble.append(inner);

    const time = document.createElement("div");
    time.className = "time";

    const date = new Date(m.created_at);

    time.textContent = Number.isNaN(date.getTime())
        ? ""
        : date.toLocaleString();

    wrap.append(name, bubble, time);

    const box = $("messages");

    box.append(wrap);
    box.scrollTop = box.scrollHeight;
}

$("messageForm").onsubmit = (e) => {
    e.preventDefault();

    const text = $("messageInput").value.trim();

    if (
        !text ||
        !socket ||
        socket.readyState !== WebSocket.OPEN
    ) {
        return;
    }

    socket.send(
        JSON.stringify({
            type: "message",
            text
        })
    );

    $("messageInput").value = "";
};

$("leaveBtn").onclick = () => {
    socket?.close();
    socket = null;

    chat.classList.add("hidden");
    room.classList.remove("hidden");

    currentRoom = "";
};

$("logoutBtn").onclick = async () => {
    try {
        await api("/api/auth/logout", {
            method: "POST"
        });
    } finally {
        location.reload();
    }
};

void init();