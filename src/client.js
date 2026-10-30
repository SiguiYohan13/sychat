let authMode = "login";
let csrf = "";
let socket = null;
let currentRoom = "";
let currentUser = "";
let wsTicket = "";

const $ = (id) => document.getElementById(id);

// Force the selectors to run ONLY after the index.html finishes parsing
document.addEventListener("DOMContentLoaded", () => {
    const auth = $("auth-modal");
    const room = $("room-modal");
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
        if (auth) auth.classList.remove("hidden");
        if (room) room.classList.add("hidden");
        if (chat) chat.classList.add("hidden");
    }

    function enterRoomSelection(username) {
        currentUser = username;

        if (auth) auth.classList.add("hidden");
        if (room) room.classList.remove("hidden");
        if (chat) chat.classList.add("hidden");

        const meDisplay = $("me");
        if (meDisplay) meDisplay.textContent = username;
    }

    const loginTab = $("loginTab");
    if (loginTab) {
        loginTab.onclick = () => {
            authMode = "login";
            loginTab.classList.add("active");
            $("signupTab")?.classList.remove("active");
            const authSubmit = $("authSubmit");
            if (authSubmit) authSubmit.textContent = "Login";
        };
    }

    const signupTab = $("signupTab");
    if (signupTab) {
        signupTab.onclick = () => {
            authMode = "register";
            signupTab.classList.add("active");
            $("loginTab")?.classList.remove("active");
            const authSubmit = $("authSubmit");
            if (authSubmit) authSubmit.textContent = "Create account";
        };
    }

    if (authForm) {
        authForm.onsubmit = async (e) => {
            e.preventDefault();
            const authError = $("authError");
            if (authError) authError.textContent = "";

            try {
                const data = await api(
                    authMode === "login"
                        ? "/api/auth/login"
                        : "/api/auth/register",
                    {
                        method: "POST",
                        body: JSON.stringify({
                            username: $("username")?.value,
                            password: $("password")?.value
                        })
                    }
                );

                currentUser = data.username;
                enterRoomSelection(currentUser);
            } catch (err) {
                if (authError) {
                    authError.textContent =
                        err instanceof Error ? err.message : "Request failed.";
                }
            }
        };
    }

    const roomForm = $("roomForm");
    if (roomForm) {
        roomForm.onsubmit = async (e) => {
            e.preventDefault();
            const roomError = $("roomError");
            if (roomError) roomError.textContent = "";

            const roomNameEl = $("roomName");
            const name = roomNameEl ? roomNameEl.value.trim() : "";

            try {
                await api("/api/rooms/join", {
                    method: "POST",
                    body: JSON.stringify({ name })
                });

                await openChat(name);
            } catch (err) {
                if (roomError) {
                    roomError.textContent =
                        err instanceof Error ? err.message : "Could not join room.";
                }
            }
        };
    }

    async function openChat(name) {
        currentRoom = name;

        if (room) room.classList.add("hidden");
        if (chat) chat.classList.remove("hidden");

        const chatTitle = $("chatTitle");
        if (chatTitle) chatTitle.textContent = "#" + name;
        
        const onlineState = $("onlineState");
        if (onlineState) onlineState.textContent = "Loading…";
        
        const messages = $("messages");
        if (messages) messages.innerHTML = "";

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
            const onlineState = $("onlineState");
            if (onlineState) onlineState.textContent = "Online";
        };

        socket.onclose = () => {
            const onlineState = $("onlineState");
            if (onlineState) onlineState.textContent = "Offline";
        };

        socket.onerror = (error) => {
            console.error("WebSocket error:", error);
            const onlineState = $("onlineState");
            if (onlineState) onlineState.textContent = "Offline";
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
        wrap.className = "msg" + (m.username === currentUser ? " mine" : "");

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
        if (box) {
            box.append(wrap);
            box.scrollTop = box.scrollHeight;
        }
    }

    const messageForm = $("messageForm");
    if (messageForm) {
        messageForm.onsubmit = (e) => {
            e.preventDefault();
            const messageInput = $("messageInput");
            const text = messageInput ? messageInput.value.trim() : "";

            if (!text || !socket || socket.readyState !== WebSocket.OPEN) {
                return;
            }

            socket.send(
                JSON.stringify({
                    type: "message",
                    text
                })
            );

            if (messageInput) messageInput.value = "";
        };
    }

    const leaveBtn = $("leaveBtn");
    if (leaveBtn) {
        leaveBtn.onclick = () => {
            socket?.close();
            socket = null;

            if (chat) chat.classList.add("hidden");
            if (room) room.classList.remove("hidden");

            currentRoom = "";
        };
    }

    const logoutBtn = $("logoutBtn");
    if (logoutBtn) {
        logoutBtn.onclick = async () => {
            try {
                await api("/api/auth/logout", {
                    method: "POST"
                });
            } finally {
                location.reload();
            }
        };
    }

    // Fire the initial route check loop
    void init();
});
