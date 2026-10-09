/* SY Chat Web - client
 * Written for index.html + server.ts (REST + WebSocket ticket auth).
 * No inline styles/handlers: compatible with the server's strict CSP.
 */
(() => {
    "use strict";

    /* ------------------------------------------------------------------ */
    /* Constants / state                                                  */
    /* ------------------------------------------------------------------ */

    const LAST_ROOM_KEY = "sy_last_room";
    const USERNAME_RE = /^[A-Za-z0-9_]+(?: [A-Za-z0-9_]+)?$/;
    const ROOM_RE = /^[A-Za-z0-9_-]{1,64}$/;

    const MAX_TEXT = 2000;
    const MAX_IMAGE_BYTES = 2 * 1024 * 1024;
    const MAX_VIDEO_BYTES = 5 * 1024 * 1024;
    const AVATAR_MAX_BYTES = 512 * 1024;
    const AVATAR_SIZE = 256;
    const MAX_AUDIO_SECONDS = 60;
    const MAX_VIDEO_SECONDS = 30;
    const MAX_RECONNECT_ATTEMPTS = 6;

    const GIF_CATEGORIES = [
        "Trending", "Funny", "Reactions", "Love", "Sad", "Celebration", "Cool"
    ];

    const IMAGE_DATA_RE = /^data:image\/(?:png|jpe?g|gif|webp);base64,/i;
    const AUDIO_DATA_RE = /^data:audio\/(?:webm|ogg|mp4|mpeg|wav|aac|x-m4a)(?:;[^,;]*)*;base64,/i;
    const VIDEO_DATA_RE = /^data:video\/(?:webm|mp4|ogg|quicktime)(?:;[^,;]*)*;base64,/i;

    const state = {
        csrf: "",
        user: null,              // { username, isAdmin }
        room: "",
        canManage: false,        // room owner or global admin
        socket: null,
        closingSocket: false,
        reconnectTimer: null,
        reconnectAttempts: 0,
        needsResync: false,
        banTimer: null,
        seen: new Set(),
        notifications: [],
        report: null,            // { reportedUser, text }
        uploadKind: "image",
        gifCategory: GIF_CATEGORIES[0],
        gifQuery: "",
        gifRequestId: 0,
        gifSearchTimer: null,
        recorder: null,          // voice recorder
        recorderChunks: [],
        recorderTimer: null,
        recorderStartedAt: 0,
        cameraStream: null,
        cameraMode: "photo",
        cameraRecorder: null,
        cameraChunks: [],
        cameraTimer: null,
        cameraStartedAt: 0,
        cameraDiscard: false,
        cameraPurpose: "message", // "message" | "avatar"
        avatarVersion: Date.now(),
        adminTag: null,
        birthDate: undefined      // undefined = not loaded, null = not set
    };

    /* ------------------------------------------------------------------ */
    /* Small helpers                                                      */
    /* ------------------------------------------------------------------ */

    const $ = (id) => document.getElementById(id);

    function show(node) { node?.classList.remove("hidden"); }
    function hide(node) { node?.classList.add("hidden"); }

    function setError(node, message) {
        if (!node) return;
        node.textContent = message || "";
        if (message) show(node); else hide(node);
    }

    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = String(text);
        return node;
    }

    function buttonByText(root, text) {
        if (!root) return null;
        const needle = text.toLowerCase();
        return [...root.querySelectorAll("button")].find(
            (b) => b.textContent.trim().toLowerCase().includes(needle)
        ) || null;
    }

    function buttonsByText(root, text) {
        if (!root) return [];
        const needle = text.toLowerCase();
        return [...root.querySelectorAll("button")].filter(
            (b) => b.textContent.trim().toLowerCase().includes(needle)
        );
    }

    function on(node, eventName, handler) {
        node?.addEventListener(eventName, handler);
    }

    function toast(message) {
        const frame = el(
            "div",
            "p-[2px] rounded-xl bg-gradient-to-r from-blue-600 via-red-500 to-yellow-400 shadow-xl"
        );
        Object.assign(frame.style, {
            position: "fixed",
            left: "50%",
            bottom: "90px",
            transform: "translateX(-50%)",
            zIndex: "200",
            maxWidth: "90vw"
        });
        frame.appendChild(
            el("div", "bg-slate-900 text-white text-xs font-medium px-4 py-2.5 rounded-xl", message)
        );
        document.body.appendChild(frame);
        setTimeout(() => frame.remove(), 3500);
    }

    function formatTime(value) {
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return "";
        return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    }

    function formatDateTime(value) {
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return "";
        return date.toLocaleString();
    }

    function blobToDataUrl(blob) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(String(reader.result || ""));
            reader.onerror = () => reject(reader.error || new Error("Could not read file."));
            reader.readAsDataURL(blob);
        });
    }

    function pickMime(candidates) {
        if (typeof MediaRecorder === "undefined") return "";
        return candidates.find((m) => MediaRecorder.isTypeSupported(m)) || "";
    }

    function formatClock(seconds) {
        const m = String(Math.floor(seconds / 60)).padStart(2, "0");
        const s = String(seconds % 60).padStart(2, "0");
        return `${m}:${s}`;
    }

    function isGiphyUrl(value) {
        try {
            const url = new URL(String(value));
            return url.protocol === "https:" &&
                (url.hostname === "giphy.com" || url.hostname.endsWith(".giphy.com"));
        } catch (_) {
            return false;
        }
    }

    function rememberRoom(name) {
        try { localStorage.setItem(LAST_ROOM_KEY, name); } catch (_) {}
    }

    function forgetRoom() {
        try { localStorage.removeItem(LAST_ROOM_KEY); } catch (_) {}
    }

    function lastRoom() {
        try { return localStorage.getItem(LAST_ROOM_KEY) || ""; } catch (_) { return ""; }
    }

    /* ------------------------------------------------------------------ */
    /* API                                                                */
    /* ------------------------------------------------------------------ */

    async function loadCsrf() {
        const response = await fetch("/api/csrf", { credentials: "same-origin" });
        if (!response.ok) throw new Error("Could not initialize the security token.");
        const data = await response.json();
        state.csrf = String(data.csrfToken || data.token || "");
    }

    async function api(path, options = {}, retried = false) {
        const method = String(options.method || "GET").toUpperCase();
        const headers = new Headers(options.headers || {});

        if (options.body !== undefined && !headers.has("Content-Type")) {
            headers.set("Content-Type", "application/json");
        }
        if (method !== "GET") headers.set("X-CSRF-Token", state.csrf);

        const response = await fetch(path, {
            ...options,
            method,
            headers,
            credentials: "same-origin"
        });

        let data = null;
        if (response.status !== 204) {
            data = await response.json().catch(() => null);
        }

        if (!response.ok) {
            if (response.status === 403 && data?.error === "Invalid CSRF token." && !retried) {
                await loadCsrf();
                return api(path, options, true);
            }

            const error = new Error(
                response.status === 429
                    ? "Too many requests. Please wait a moment and try again."
                    : data?.error || `Request failed (${response.status}).`
            );
            error.status = response.status;
            error.data = data;
            throw error;
        }

        return data;
    }

    function post(path, body) {
        return api(path, { method: "POST", body: JSON.stringify(body ?? {}) });
    }

    /* ------------------------------------------------------------------ */
    /* Avatars                                                            */
    /* ------------------------------------------------------------------ */

    function avatarUrl(username, version) {
        const base = `/api/avatars/${encodeURIComponent(username)}`;
        return version ? `${base}?v=${version}` : base;
    }

    const AVATAR_COLORS = [
        "bg-amber-600", "bg-blue-600", "bg-emerald-600", "bg-cyan-600",
        "bg-pink-600", "bg-purple-600", "bg-orange-600", "bg-yellow-600",
        "bg-brown-600", "bg-beige-600", "bg-emerald-700"
    ];

    function avatarColorClass(username) {
        let hash = 0;
        for (const ch of String(username)) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
        return AVATAR_COLORS[hash % AVATAR_COLORS.length];
    }

    function makeAvatar(username, size, version, isAdmin) {
        const ring = el(
            "span",
            "bg-gradient-to-r from-blue-600 via-red-500 to-yellow-400 rounded-full shrink-0"
        );
        Object.assign(ring.style, { display: "inline-flex", padding: "2px" });

        const circle = el(
            "span",
            `${avatarColorClass(username)} rounded-full overflow-hidden relative text-white font-bold`
        );
        Object.assign(circle.style, {
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            width: size + "px",
            height: size + "px",
            fontSize: Math.max(9, Math.round(size * 0.5)) + "px",
            lineHeight: "1"
        });
        circle.textContent = (username || "?")[0].toUpperCase();

        const img = el("img");
        img.alt = "";
        Object.assign(img.style, {
            position: "absolute",
            inset: "0",
            width: "100%",
            height: "100%",
            objectFit: "cover"
        });
        on(img, "load", () => { circle.textContent = ""; circle.appendChild(img); });
        on(img, "error", () => img.remove());
        img.src = avatarUrl(username, version);

        if (isAdmin) {
            ring.classList.add("admin-avatar");
            ring.dataset.admin = "1";
        }

        ring.appendChild(circle);
        return ring;
    }

    function renderProfileAvatar() {
        const preview = $("profile-avatar-preview");
        if (!preview || !state.user) return;

        const username = state.user.username;
        const initial = $("profile-avatar-initial") || el("span");
        initial.id = "profile-avatar-initial";
        initial.textContent = username[0].toUpperCase();
        show(initial);

        preview.className =
            "profile-avatar-preview bg-gradient-to-r from-blue-600 via-red-500 to-yellow-400 rounded-full p-[3px] gradient-glow";
        preview.style.display = "inline-flex";

        const circle = el(
            "div",
            `${avatarColorClass(username)} rounded-full overflow-hidden relative flex items-center justify-center text-white font-bold`
        );
        Object.assign(circle.style, { width: "96px", height: "96px", fontSize: "40px" });
        circle.appendChild(initial);
        preview.replaceChildren(circle);

        const img = el("img");
        img.alt = "";
        Object.assign(img.style, {
            position: "absolute",
            inset: "0",
            width: "100%",
            height: "100%",
            objectFit: "cover"
        });
        on(img, "load", () => hide(initial));
        on(img, "error", () => img.remove());
        img.src = avatarUrl(username, state.avatarVersion);
        circle.appendChild(img);
    }

    async function loadImageSource(blob) {
        if (typeof createImageBitmap === "function") {
            return createImageBitmap(blob);
        }

        return new Promise((resolve, reject) => {
            const url = URL.createObjectURL(blob);
            const img = new Image();
            img.onload = () => { URL.revokeObjectURL(url); resolve(img); };
            img.onerror = () => { URL.revokeObjectURL(url); reject(new Error("Could not read the image.")); };
            img.src = url;
        });
    }

    function canvasToBlob(canvas, type, quality) {
        return new Promise((resolve) => canvas.toBlob(resolve, type, quality));
    }

    /* Center-crops any image source to a square and encodes it. */
    async function squareAvatarBlob(source) {
        const width = source.videoWidth || source.width;
        const height = source.videoHeight || source.height;
        const side = Math.min(width, height);

        const canvas = document.createElement("canvas");
        canvas.width = AVATAR_SIZE;
        canvas.height = AVATAR_SIZE;

        canvas.getContext("2d").drawImage(
            source,
            (width - side) / 2, (height - side) / 2, side, side,
            0, 0, AVATAR_SIZE, AVATAR_SIZE
        );

        let blob = await canvasToBlob(canvas, "image/webp", 0.85);
        if (!blob || blob.type !== "image/webp") {
            blob = await canvasToBlob(canvas, "image/jpeg", 0.88);
        }

        return blob;
    }

    async function uploadAvatarBlob(blob) {
        if (!blob || !blob.size) throw new Error("Could not prepare the image.");
        if (blob.size > AVATAR_MAX_BYTES) throw new Error("Image is too large (max 512 KB).");

        await api("/api/profile/avatar", {
            method: "PUT",
            headers: { "Content-Type": blob.type },
            body: blob
        });

        state.avatarVersion = Date.now();
        renderUserHeader();
        renderProfileAvatar();
        toast("Avatar updated.");
    }

    async function handleAvatarFile(event) {
        const input = event.target;
        const file = input.files?.[0];
        input.value = "";

        if (!file) return;

        try {
            if (!/^image\/(png|jpe?g|gif|webp)$/i.test(file.type)) {
                throw new Error("Use a PNG, JPEG, WebP or GIF image.");
            }

            if (file.type === "image/gif") {
                /* Keep animation: send the GIF as is. */
                if (file.size > AVATAR_MAX_BYTES) {
                    throw new Error("GIF is too large (max 512 KB).");
                }
                await uploadAvatarBlob(file);
                return;
            }

            const source = await loadImageSource(file);
            await uploadAvatarBlob(await squareAvatarBlob(source));
        } catch (error) {
            toast(error.message || "Could not update the avatar.");
        }
    }

    async function removeAvatar() {
        try {
            await api("/api/profile/avatar", { method: "DELETE" });
            state.avatarVersion = Date.now();
            renderUserHeader();
            renderProfileAvatar();
            toast("Avatar removed.");
        } catch (error) {
            toast(error.message || "Could not remove the avatar.");
        }
    }

    /* ------------------------------------------------------------------ */
    /* Session / authentication                                           */
    /* ------------------------------------------------------------------ */

    function showAuth(message) {
        show($("auth-modal"));
        hide($("room-modal"));
        showLoginForm();
        if (message) setError($("login-user-error"), message);
    }

    function showLoginForm() {
        show($("login-form"));
        hide($("create-form"));
    }

    function showCreateForm() {
        hide($("login-form"));
        show($("create-form"));
    }

    function makeAdminBadge() {
        return el("span", "admin-badge", "Admin");
    }

    function updateAdminMenu() {
        const adminItem = $("admin-menu-option");

        if (adminItem) {
            if (state.canManage && state.room) {
                show(adminItem);
                adminItem.classList.add("flex");
            } else {
                hide(adminItem);
                adminItem.classList.remove("flex");
            }
        }

        /* Room owner: Admin badge next to the username in the header */
        const display = $("current-user-display");
        if (display) {
            display.querySelector("[data-owner-badge]")?.remove();

            if (state.canManage && state.room) {
                const badge = makeAdminBadge();
                badge.dataset.ownerBadge = "1";
                display.appendChild(badge);
            }
        }
    }

    function renderUserHeader() {
        const username = state.user?.username || "";
        const display = $("current-user-display");
        if (display) {
            display.replaceChildren(
                ...(username
                    ? [makeAvatar(username, 18, state.avatarVersion), document.createTextNode(username)]
                    : [])
            );
        }

        renderProfileAvatar();

        updateAdminMenu();
    }

    async function onAuthenticated(me) {
        state.user = { username: me.username, isAdmin: Boolean(me.isAdmin) };
        state.avatarVersion = Date.now();

        hide($("auth-modal"));
        document.body.classList.add("logged-in");
        renderUserHeader();

        clearInterval(state.banTimer);
        state.banTimer = setInterval(checkSession, 30000);

        loadNotifications();

        const saved = lastRoom();
        if (saved && ROOM_RE.test(saved)) {
            try {
                const joined = await post("/api/rooms/join", { name: saved });
                await enterRoom(saved, Boolean(joined?.canManage));
                return;
            } catch (_) {
                forgetRoom();
            }
        }

        showRoomModal();
    }

    async function submitAuth(mode) {
        const isLogin = mode === "login";
        const userInput = $(isLogin ? "login-username" : "create-username");
        const passInput = $(isLogin ? "login-password" : "create-password");
        const userError = $(isLogin ? "login-user-error" : "create-user-error");
        const passError = $(isLogin ? "login-pass-error" : "create-pass-error");
        const button = $(isLogin ? "login-btn" : "create-btn");

        setError(userError, "");
        setError(passError, "");

        const username = (userInput?.value || "").trim();
        const password = String(passInput?.value || "");

        if (username.length < 4 || username.length > 20 || !USERNAME_RE.test(username)) {
            setError(userError, "4-20 characters: letters, numbers, underscore (one space allowed).");
            return;
        }

        if (password.length < 8 || password.length > 128) {
            setError(passError, "Password must be 8 to 128 characters.");
            return;
        }

        if (button) button.disabled = true;

        try {
            const data = await post(
                isLogin ? "/api/auth/login" : "/api/auth/register",
                { username, password }
            );

            if (data?.csrfToken) state.csrf = String(data.csrfToken);
            if (passInput) passInput.value = "";

            await onAuthenticated(data);
        } catch (error) {
            setError(passError, error.message || "Request failed.");
        } finally {
            if (button) button.disabled = false;
        }
    }

    function cleanupSession() {
        clearInterval(state.banTimer);
        state.banTimer = null;

        closeSocket();
        stopVoiceRecording(true);
        closeCamera();

        state.user = null;
        state.birthDate = undefined;
        state.room = "";
        state.canManage = false;
        state.seen.clear();
        state.notifications = [];

        $("chat-messages")?.replaceChildren();
        const roomDisplay = $("current-room-display");
        if (roomDisplay) roomDisplay.textContent = "";
        const userDisplay = $("current-user-display");
        if (userDisplay) userDisplay.replaceChildren();

        document.body.classList.remove("logged-in");

        [
            "room-modal", "report-modal", "notifications-modal", "profile-modal",
            "gif-library-modal", "admin-modal", "camera-modal", "events-modal"
        ].forEach((id) => hide($(id)));

        hide($("dropdown-menu"));
        $("upload-menu")?.classList.remove("visible");
    }

    async function logout(message) {
        try {
            await post("/api/auth/logout", {});
        } catch (_) {
            /* session may already be gone */
        }

        cleanupSession();
        forgetRoom();

        try { await loadCsrf(); } catch (_) {}

        showAuth(message);
    }

    async function checkSession() {
        try {
            const me = await api("/api/me");
            if (me?.banned) {
                await logout(me.banMessage || "Your account is banned.");
            }
        } catch (error) {
            if (error.status === 401) {
                await logout("Your session has expired. Please log in again.");
            }
        }
    }

    /* ------------------------------------------------------------------ */
    /* Rooms                                                              */
    /* ------------------------------------------------------------------ */

    function showRoomModal() {
        setError($("room-error"), "");
        show($("room-modal"));
        $("room-name-input")?.focus();
    }

    async function joinRoom() {
        const input = $("room-name-input");
        const name = String(input?.value || "").trim().toLowerCase();

        setError($("room-error"), "");

        if (!name) {
            setError($("room-error"), "Please enter a room name.");
            return;
        }

        if (!ROOM_RE.test(name)) {
            setError($("room-error"), "Use letters, numbers, - and _ only (max 64).");
            return;
        }

        try {
            const joined = await post("/api/rooms/join", { name });
            if (input) input.value = "";
            await enterRoom(name, Boolean(joined?.canManage));
        } catch (error) {
            setError($("room-error"), error.message || "Could not join the room.");
        }
    }

    async function enterRoom(name, canManage = false) {
        state.room = name;
        state.canManage = canManage;
        updateAdminMenu();
        state.seen.clear();
        state.needsResync = false;

        $("chat-messages")?.replaceChildren();
        const roomDisplay = $("current-room-display");
        if (roomDisplay) roomDisplay.textContent = "#" + name;

        hide($("room-modal"));
        rememberRoom(name);

        await loadHistory();
        await connectSocket();
    }

    function leaveRoom(showSelection = true) {
        const wasInRoom = Boolean(state.room);

        state.room = "";
        state.canManage = false;
        updateAdminMenu();
        state.seen.clear();
        closeSocket();
        stopVoiceRecording(true);

        $("chat-messages")?.replaceChildren();
        const roomDisplay = $("current-room-display");
        if (roomDisplay) roomDisplay.textContent = "";

        hide($("admin-modal"));
        hide($("gif-library-modal"));
        $("upload-menu")?.classList.remove("visible");

        if (wasInRoom) forgetRoom();
        if (showSelection && state.user) showRoomModal();
    }

    async function loadHistory() {
        if (!state.room) return;

        try {
            const data = await api(`/api/rooms/${encodeURIComponent(state.room)}/messages`);
            const messages = Array.isArray(data?.messages) ? data.messages : [];
            messages.forEach(appendMessage);
        } catch (error) {
            toast(error.message || "Could not load messages.");
        }
    }

    /* ------------------------------------------------------------------ */
    /* WebSocket                                                          */
    /* ------------------------------------------------------------------ */

    function setConnectionLabel(text) {
        const title = $("header-title");
        if (title) title.textContent = text ? `SY Chat Web - ${text}` : "SY Chat Web";
    }

    function closeSocket() {
        clearTimeout(state.reconnectTimer);
        state.reconnectTimer = null;

        const socket = state.socket;
        state.socket = null;

        if (socket) {
            state.closingSocket = true;
            try { socket.close(); } catch (_) {}
            state.closingSocket = false;
        }

        setConnectionLabel("");
    }

    async function connectSocket() {
        const room = state.room;
        if (!room) return;

        clearTimeout(state.reconnectTimer);
        setConnectionLabel("connecting...");

        let ticket = "";

        try {
            const data = await post("/api/ws-ticket", {});
            ticket = String(data?.ticket || "");
        } catch (error) {
            if (error.status === 403 || error.status === 401) {
                await logout(error.message);
                return;
            }
            scheduleReconnect();
            return;
        }

        if (!ticket || room !== state.room) return;

        const protocol = location.protocol === "https:" ? "wss:" : "ws:";
        const socket = new WebSocket(
            `${protocol}//${location.host}/ws?ticket=${encodeURIComponent(ticket)}`
        );

        state.socket = socket;

        socket.addEventListener("open", () => {
            socket.send(JSON.stringify({ type: "join", room }));
        });

        socket.addEventListener("message", (event) => handleSocketMessage(event.data));

        socket.addEventListener("close", () => {
            if (state.socket === socket) state.socket = null;
            if (state.closingSocket || room !== state.room) return;
            setConnectionLabel("reconnecting...");
            scheduleReconnect();
        });

        socket.addEventListener("error", () => { /* close handler does the work */ });
    }

    function scheduleReconnect() {
        if (!state.room || !state.user) return;

        if (state.reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
            setConnectionLabel("offline");
            toast("Connection lost. Re-enter the room to reconnect.");
            return;
        }

        state.reconnectAttempts += 1;
        state.needsResync = true;

        const delay = Math.min(1000 * 2 ** state.reconnectAttempts, 15000);
        clearTimeout(state.reconnectTimer);
        state.reconnectTimer = setTimeout(connectSocket, delay);
    }

    function handleSocketMessage(raw) {
        let payload;

        try {
            payload = JSON.parse(raw);
        } catch (_) {
            return;
        }

        switch (payload?.type) {
            case "joined":
                state.reconnectAttempts = 0;
                setConnectionLabel("");
                if (state.needsResync) {
                    state.needsResync = false;
                    loadHistory();
                }
                break;

            case "message":
                if (payload.message) appendMessage(payload.message);
                break;

            case "notification":
                toast(String(payload.text || "New notification"));
                loadNotifications();
                break;

            case "banned":
                logout(`You have been banned until ${formatDateTime(payload.until)}.`);
                break;

            case "room_deleted":
                toast(String(payload.text || "This room was deleted."));
                leaveRoom(true);
                break;

            case "kicked":
                toast(String(payload.text || "You were banned from this room."));
                leaveRoom(true);
                break;

            case "new_report":
                if (state.canManage && payload.room === state.room) {
                    toast("A new report was submitted in this room.");
                    if (!$("admin-modal")?.classList.contains("hidden")) refreshAdmin();
                }
                break;

            case "error":
                toast(String(payload.error || "Chat error."));
                break;

            default:
                break;
        }
    }

    function sendMessage(text, metadata) {
        const socket = state.socket;

        if (!socket || socket.readyState !== WebSocket.OPEN || !state.room) {
            toast("Not connected to the chat yet.");
            return false;
        }

        const payload = { type: "message", room: state.room, text: text || "" };
        if (metadata) payload.metadata = metadata;

        socket.send(JSON.stringify(payload));
        return true;
    }

    /* ------------------------------------------------------------------ */
    /* Message rendering                                                  */
    /* ------------------------------------------------------------------ */

    function buildMedia(metadata) {
        const type = metadata?.type;
        const url = String(metadata?.url || "");

        if ((type === "gif" && isGiphyUrl(url)) || (type === "image" && IMAGE_DATA_RE.test(url))) {
            const img = el("img", "rounded-lg object-contain");
            img.src = url;
            img.alt = type === "gif" ? "GIF" : String(metadata.name || "image");
            img.loading = "lazy";
            img.style.maxHeight = "320px";
            return img;
        }

        if (type === "video" && VIDEO_DATA_RE.test(url)) {
            const video = el("video", "rounded-lg");
            video.controls = true;
            video.preload = "metadata";
            video.playsInline = true;
            video.src = url;
            video.style.maxHeight = "320px";
            return video;
        }

        if (type === "audio" && AUDIO_DATA_RE.test(url)) {
            /* Same gradient "recorded message" player as the rest of the design. */
            const wrapper = el("div", "recorded-message");
            const inner = el("div", "recorded-message-inner");
            const audio = el("audio");
            audio.controls = true;
            audio.src = url;
            inner.appendChild(audio);
            wrapper.appendChild(inner);
            wrapper.dataset.kind = "audio";
            return wrapper;
        }

        return null;
    }

    function appendMessage(message) {
        const container = $("chat-messages");
        if (!container || !message) return;

        const id = message.id;
        if (id !== undefined && id !== null) {
            if (state.seen.has(String(id))) return;
            state.seen.add(String(id));
        }

        const username = String(message.username || "");
        const text = String(message.text || "");
        const metadata = message.metadata && typeof message.metadata === "object" ? message.metadata : {};
        const own = username === state.user?.username;

        const nearBottom =
            container.scrollHeight - container.scrollTop - container.clientHeight < 120;

        const row = el("div", own ? "flex justify-end mb-3" : "flex justify-start mb-3");
        const column = el("div", "max-w-md");
        column.style.minWidth = "0";

        const isAdminMessage = Boolean(message.is_admin);

        if (!own || isAdminMessage) {
            const sender = el(
                "div",
                own ? "flex items-center justify-end gap-2 mb-1" : "flex items-center gap-2 mb-1"
            );

            if (!own) {
                sender.append(
                    makeAvatar(username, 22, undefined, isAdminMessage),
                    el("span", "text-xs font-semibold text-indigo-300", username)
                );
            }

            if (isAdminMessage) sender.appendChild(makeAdminBadge());
            column.appendChild(sender);
        }

        const media = buildMedia(metadata);
        const isAudio = media?.dataset?.kind === "audio";

        if (isAudio) {
            column.appendChild(media);
            if (text) {
                const caption = el("div", "text-sm text-slate-200 whitespace-pre-wrap mt-1", text);
                caption.style.overflowWrap = "anywhere";
                column.appendChild(caption);
            }
        } else {
            /* Gradient frame (blue -> red -> yellow) around an indigo bubble. */
            const frame = el(
                "div",
                "p-[2px] rounded-2xl bg-gradient-to-r from-blue-600 via-red-500 to-yellow-400 shadow-lg"
            );
            const bubble = el(
                "div",
                `${own ? "bg-indigo-600 text-white" : "bg-indigo-950 text-slate-100"} rounded-xl px-4 py-3`
            );

            if (media) {
                bubble.appendChild(media);
            }

            if (text) {
                const body = el("div", `text-sm whitespace-pre-wrap${media ? " mt-2" : ""}`, text);
                body.style.overflowWrap = "anywhere";
                bubble.appendChild(body);
            } else if (!media && metadata?.type) {
                bubble.appendChild(el("div", "text-xs text-slate-300", "[unsupported attachment]"));
            }

            frame.appendChild(bubble);
            column.appendChild(frame);
        }

        const footer = el("div", `flex items-center gap-2 mt-1${own ? " justify-end" : ""}`);
        footer.appendChild(el("span", "text-[10px] text-slate-500", formatTime(message.created_at)));

        if (!own && username) {
            const report = el("button", "text-[10px] text-slate-400 hover:text-red-400 transition", "Report");
            report.type = "button";
            report.title = "Report this message";
            Object.assign(report.style, { background: "none", padding: "0" });
            on(report, "click", () => openReport(username, text || "[media message]"));
            footer.appendChild(report);
        }

        column.appendChild(footer);
        row.appendChild(column);
        container.appendChild(row);

        if (own || nearBottom) container.scrollTop = container.scrollHeight;
    }

    /* ------------------------------------------------------------------ */
    /* Composer                                                           */
    /* ------------------------------------------------------------------ */

    function sendTypedMessage() {
        const input = $("message-input");
        const text = String(input?.value || "").trim();

        if (!text) return;

        if (text.length > MAX_TEXT) {
            toast(`Messages are limited to ${MAX_TEXT} characters.`);
            return;
        }

        if (sendMessage(text) && input) {
            input.value = "";
            input.style.height = "auto";
        }
    }

    function autoGrowInput() {
        const input = $("message-input");
        if (!input) return;
        input.style.height = "auto";
        input.style.height = Math.min(input.scrollHeight, 128) + "px";
    }

    /* ------------------------------------------------------------------ */
    /* Uploads (image / video from files)                                 */
    /* ------------------------------------------------------------------ */

    function toggleUploadMenu() {
        const menu = $("upload-menu");
        const button = $("upload-btn");
        if (!menu) return;
        const open = menu.classList.toggle("visible");
        button?.setAttribute("aria-expanded", String(open));
    }

    function closeUploadMenu() {
        $("upload-menu")?.classList.remove("visible");
        $("upload-btn")?.setAttribute("aria-expanded", "false");
    }

    function pickFile(kind) {
        const input = $("upload-input");
        if (!input) return;
        state.uploadKind = kind;
        input.accept = kind === "video" ? "video/*" : "image/*";
        closeUploadMenu();
        input.click();
    }

    async function handleUploadChange(event) {
        const input = event.target;
        const file = input.files?.[0];
        input.value = "";

        if (!file) return;

        const isVideo = state.uploadKind === "video";
        const limit = isVideo ? MAX_VIDEO_BYTES : MAX_IMAGE_BYTES;

        if (file.size > limit) {
            toast(`File too large (max ${Math.round(limit / 1024 / 1024)} MB).`);
            return;
        }

        try {
            const dataUrl = await blobToDataUrl(file);
            const accepted = isVideo ? VIDEO_DATA_RE : IMAGE_DATA_RE;

            if (!accepted.test(dataUrl)) {
                toast("This file type is not supported.");
                return;
            }

            sendMessage("", {
                type: isVideo ? "video" : "image",
                url: dataUrl,
                mimeType: file.type,
                name: String(file.name || "").slice(0, 120)
            });
        } catch (error) {
            toast(error.message || "Could not upload the file.");
        }
    }

    /* ------------------------------------------------------------------ */
    /* Voice messages                                                     */
    /* ------------------------------------------------------------------ */

    async function startVoiceRecording() {
        if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === "undefined") {
            toast("Voice recording is not supported in this browser.");
            return;
        }

        let stream;

        try {
            stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        } catch (_) {
            toast("Microphone access was denied.");
            return;
        }

        const mimeType = pickMime([
            "audio/webm;codecs=opus", "audio/webm", "audio/ogg;codecs=opus", "audio/mp4"
        ]);

        const recorder = new MediaRecorder(stream, mimeType ? { mimeType } : undefined);
        const baseType = (mimeType || recorder.mimeType || "audio/webm").split(";")[0];

        state.recorder = recorder;
        state.recorderChunks = [];
        state.recorder.discard = false;

        recorder.addEventListener("dataavailable", (event) => {
            if (event.data?.size) state.recorderChunks.push(event.data);
        });

        recorder.addEventListener("stop", async () => {
            stream.getTracks().forEach((track) => track.stop());
            clearInterval(state.recorderTimer);
            hide($("recording-status"));
            $("record-btn")?.classList.remove("recording-pulse");

            const chunks = state.recorderChunks;
            const discard = recorder.discard;

            state.recorder = null;
            state.recorderChunks = [];

            if (discard || !chunks.length) return;

            const blob = new Blob(chunks, { type: baseType });

            if (blob.size > MAX_IMAGE_BYTES) {
                toast("Voice message is too large.");
                return;
            }

            try {
                const url = await blobToDataUrl(blob);
                if (!AUDIO_DATA_RE.test(url)) {
                    toast("Voice format not supported.");
                    return;
                }
                sendMessage("", { type: "audio", url, mimeType: baseType });
            } catch (error) {
                toast(error.message || "Could not send the voice message.");
            }
        });

        recorder.start();
        $("record-btn")?.classList.add("recording-pulse");
        state.recorderStartedAt = Date.now();

        const timer = $("recording-timer");
        if (timer) timer.textContent = "00:00";
        show($("recording-status"));

        state.recorderTimer = setInterval(() => {
            const seconds = Math.floor((Date.now() - state.recorderStartedAt) / 1000);
            if (timer) timer.textContent = formatClock(seconds);
            if (seconds >= MAX_AUDIO_SECONDS) stopVoiceRecording(false);
        }, 250);
    }

    function stopVoiceRecording(discard) {
        const recorder = state.recorder;
        if (!recorder) return;
        recorder.discard = Boolean(discard);
        if (recorder.state !== "inactive") recorder.stop();
    }

    function toggleVoiceRecording() {
        if (state.recorder) stopVoiceRecording(false);
        else startVoiceRecording();
    }

    /* ------------------------------------------------------------------ */
    /* Camera                                                             */
    /* ------------------------------------------------------------------ */

    function updateCameraUi() {
        const photo = $("camera-photo-btn");
        const video = $("camera-video-btn");
        const action = $("camera-action-btn");
        const recording = Boolean(state.cameraRecorder);

        if (action) {
            if (state.cameraMode === "photo") action.textContent = "Take Photo";
            else action.textContent = recording ? "Stop Recording" : "Start Recording";
        }

        [[photo, "photo"], [video, "video"]].forEach(([button, mode]) => {
            if (!button) return;
            button.classList.toggle("bg-indigo-600", state.cameraMode === mode);
            button.classList.toggle("bg-slate-700", state.cameraMode !== mode);
        });
    }

    async function startCameraStream(withAudio) {
        stopCameraStream();

        state.cameraStream = await navigator.mediaDevices.getUserMedia({
            video: { facingMode: "user" },
            audio: withAudio
        });

        const preview = $("camera-preview");
        if (preview) preview.srcObject = state.cameraStream;
    }

    function stopCameraStream() {
        state.cameraStream?.getTracks().forEach((track) => track.stop());
        state.cameraStream = null;
        const preview = $("camera-preview");
        if (preview) preview.srcObject = null;
    }

    async function openCamera(purpose = "message") {
        if (!navigator.mediaDevices?.getUserMedia) {
            toast("Camera is not supported in this browser.");
            return;
        }

        state.cameraMode = "photo";
        state.cameraPurpose = purpose === "avatar" ? "avatar" : "message";
        show($("camera-modal"));
        if (state.cameraPurpose === "avatar") hide($("camera-video-btn")); else show($("camera-video-btn"));
        updateCameraUi();

        try {
            await startCameraStream(false);
        } catch (_) {
            toast("Camera access was denied.");
            closeCamera();
        }
    }

    function closeCamera() {
        if (state.cameraRecorder) {
            state.cameraDiscard = true;
            if (state.cameraRecorder.state !== "inactive") state.cameraRecorder.stop();
        }

        clearInterval(state.cameraTimer);
        hide($("camera-recording-status"));
        stopCameraStream();
        hide($("camera-modal"));
        show($("camera-video-btn"));
        state.cameraPurpose = "message";
    }

    async function setCameraMode(mode) {
        if (state.cameraRecorder || state.cameraMode === mode) return;

        state.cameraMode = mode;
        updateCameraUi();

        try {
            await startCameraStream(mode === "video");
        } catch (_) {
            toast(mode === "video" ? "Microphone/camera access was denied." : "Camera access was denied.");
            state.cameraMode = "photo";
            updateCameraUi();
        }
    }

    async function takePhoto() {
        const preview = $("camera-preview");
        const canvas = $("camera-canvas");

        if (!preview?.videoWidth || !canvas) {
            toast("Camera is not ready yet.");
            return;
        }

        if (state.cameraPurpose === "avatar") {
            try {
                await uploadAvatarBlob(await squareAvatarBlob(preview));
                closeCamera();
            } catch (error) {
                toast(error.message || "Could not update the avatar.");
            }
            return;
        }

        const scale = Math.min(1, 1280 / preview.videoWidth);
        canvas.width = Math.round(preview.videoWidth * scale);
        canvas.height = Math.round(preview.videoHeight * scale);
        canvas.getContext("2d").drawImage(preview, 0, 0, canvas.width, canvas.height);

        const dataUrl = canvas.toDataURL("image/jpeg", 0.8);

        if (dataUrl.length * 0.75 > MAX_IMAGE_BYTES) {
            toast("Photo is too large.");
            return;
        }

        if (sendMessage("", { type: "image", url: dataUrl, mimeType: "image/jpeg", name: "photo.jpg" })) {
            closeCamera();
        }
    }

    function startCameraRecording() {
        if (!state.cameraStream || typeof MediaRecorder === "undefined") {
            toast("Video recording is not supported in this browser.");
            return;
        }

        const mimeType = pickMime([
            "video/webm;codecs=vp9,opus", "video/webm;codecs=vp8,opus", "video/webm", "video/mp4"
        ]);
        const baseType = (mimeType || "video/webm").split(";")[0];

        const recorder = new MediaRecorder(
            state.cameraStream,
            mimeType ? { mimeType, videoBitsPerSecond: 800000 } : { videoBitsPerSecond: 800000 }
        );

        state.cameraRecorder = recorder;
        state.cameraChunks = [];
        state.cameraDiscard = false;

        recorder.addEventListener("dataavailable", (event) => {
            if (event.data?.size) state.cameraChunks.push(event.data);
        });

        recorder.addEventListener("stop", async () => {
            clearInterval(state.cameraTimer);
            hide($("camera-recording-status"));

            const chunks = state.cameraChunks;
            const discard = state.cameraDiscard;

            state.cameraRecorder = null;
            state.cameraChunks = [];
            updateCameraUi();

            if (discard || !chunks.length) return;

            const blob = new Blob(chunks, { type: baseType });

            if (blob.size > MAX_VIDEO_BYTES) {
                toast("Video is too large. Try a shorter recording.");
                return;
            }

            try {
                const url = await blobToDataUrl(blob);
                if (VIDEO_DATA_RE.test(url) &&
                    sendMessage("", { type: "video", url, mimeType: baseType, name: "video" })) {
                    closeCamera();
                } else {
                    toast("Video format not supported.");
                }
            } catch (error) {
                toast(error.message || "Could not send the video.");
            }
        });

        recorder.start();
        state.cameraStartedAt = Date.now();
        show($("camera-recording-status"));
        updateCameraUi();

        const timer = $("camera-recording-timer");
        if (timer) timer.textContent = "00:00";

        state.cameraTimer = setInterval(() => {
            const seconds = Math.floor((Date.now() - state.cameraStartedAt) / 1000);
            if (timer) timer.textContent = formatClock(seconds);
            if (seconds >= MAX_VIDEO_SECONDS && recorder.state !== "inactive") recorder.stop();
        }, 250);
    }

    function onCameraAction() {
        if (state.cameraMode === "photo") {
            takePhoto();
        } else if (state.cameraRecorder) {
            if (state.cameraRecorder.state !== "inactive") state.cameraRecorder.stop();
        } else {
            startCameraRecording();
        }
    }

    /* ------------------------------------------------------------------ */
    /* GIF library                                                        */
    /* ------------------------------------------------------------------ */

    function openGifLibrary() {
        if (!state.room) return;
        show($("gif-library-modal"));
        renderGifTabs();
        loadGifs();
    }

    function closeGifLibrary() {
        hide($("gif-library-modal"));
    }

    function renderGifTabs() {
        const tabs = $("gif-library-tabs");
        if (!tabs) return;

        tabs.replaceChildren(
            ...GIF_CATEGORIES.map((name) => {
                const tab = el("button", "gif-library-tab", name);
                tab.type = "button";
                tab.classList.toggle("active", name === state.gifCategory);
                on(tab, "click", () => {
                    state.gifCategory = name;
                    state.gifQuery = name === GIF_CATEGORIES[0] ? "" : name;
                    const search = $("gif-library-search");
                    if (search) search.value = "";
                    renderGifTabs();
                    loadGifs();
                });
                return tab;
            })
        );
    }

    function toGif(item) {
        const images = item?.images || {};
        const previewUrl = images.fixed_height_small?.url || images.fixed_height?.url;
        const sendUrl = images.fixed_height?.url || images.original?.url;

        if (!isGiphyUrl(previewUrl) || !isGiphyUrl(sendUrl)) return null;

        return {
            title: String(item.title || "GIF").slice(0, 80),
            previewUrl,
            sendUrl
        };
    }

    function renderGifCard(gif) {
        const card = el("button", "gif-card");
        card.type = "button";
        card.title = gif.title;

        const img = el("img");
        img.src = gif.previewUrl;
        img.alt = gif.title;
        img.loading = "lazy";
        card.appendChild(img);

        on(card, "click", () => {
            if (sendMessage("", { type: "gif", url: gif.sendUrl, name: gif.title })) {
                closeGifLibrary();
            }
        });

        return card;
    }

    async function loadGifs() {
        const grid = $("gif-library-grid");
        if (!grid) return;

        const requestId = ++state.gifRequestId;
        const query = state.gifQuery.trim();

        grid.replaceChildren(el("div", "gif-loading", "Loading GIFs..."));

        const path = query
            ? `/api/gifs/search?q=${encodeURIComponent(query)}&limit=24`
            : "/api/gifs/trending?limit=24";

        try {
            const data = await api(path);
            if (requestId !== state.gifRequestId) return;

            const gifs = (Array.isArray(data?.data) ? data.data : []).map(toGif).filter(Boolean);

            grid.replaceChildren(
                ...(gifs.length ? gifs.map(renderGifCard) : [el("div", "gif-empty", "No GIFs found.")])
            );
        } catch (error) {
            if (requestId !== state.gifRequestId) return;
            grid.replaceChildren(el("div", "gif-empty", error.message || "Could not load GIFs."));
        }
    }

    function onGifSearchInput(event) {
        clearTimeout(state.gifSearchTimer);

        const value = String(event.target.value || "");

        state.gifSearchTimer = setTimeout(() => {
            state.gifQuery = value;
            state.gifCategory = value.trim() ? "" : GIF_CATEGORIES[0];
            renderGifTabs();
            loadGifs();
        }, 400);
    }

    /* ------------------------------------------------------------------ */
    /* Notifications                                                      */
    /* ------------------------------------------------------------------ */

    async function loadNotifications() {
        try {
            const data = await api("/api/notifications");
            state.notifications = Array.isArray(data?.notifications) ? data.notifications : [];
            renderNotifications();
        } catch (_) {
            /* not critical */
        }
    }

    function renderNotifications() {
        const list = $("notifications-list");
        if (!list) return;

        if (!state.notifications.length) {
            list.replaceChildren(el("p", "text-xs text-slate-400 italic", "No notifications yet."));
            return;
        }

        list.replaceChildren(
            ...state.notifications.map((item) => {
                const card = el("div", "bg-slate-900 border border-slate-700 rounded-lg p-3");
                Object.assign(card.style, {
                    display: "flex",
                    gap: "10px",
                    justifyContent: "space-between",
                    alignItems: "flex-start"
                });

                const body = el("div");
                body.appendChild(el("div", "text-xs text-slate-200", item.text));
                body.appendChild(el("div", "text-[10px] text-slate-500", formatDateTime(item.created_at)));

                const remove = el("button", "text-slate-400 hover:text-white text-xs", "✕");
                remove.type = "button";
                remove.title = "Delete";
                on(remove, "click", async () => {
                    try {
                        await api(`/api/notifications/${encodeURIComponent(item.id)}`, { method: "DELETE" });
                        state.notifications = state.notifications.filter((n) => n.id !== item.id);
                        renderNotifications();
                    } catch (error) {
                        toast(error.message || "Could not delete the notification.");
                    }
                });

                card.append(body, remove);
                return card;
            })
        );
    }

    function openNotifications() {
        hide($("dropdown-menu"));
        show($("notifications-modal"));
        loadNotifications();
    }

    /* ------------------------------------------------------------------ */
    /* Profile                                                            */
    /* ------------------------------------------------------------------ */

    function openProfile() {
        hide($("dropdown-menu"));
        ["profile-current-password", "profile-new-password", "profile-confirm-password"]
            .forEach((id) => { const input = $(id); if (input) input.value = ""; });
        setError($("profile-password-error"), "");
        renderUserHeader();
        show($("profile-modal"));
    }

    async function savePassword() {
        const current = String($("profile-current-password")?.value || "");
        const next = String($("profile-new-password")?.value || "");
        const confirm = String($("profile-confirm-password")?.value || "");
        const errorNode = $("profile-password-error");

        setError(errorNode, "");

        if (!current && !next && !confirm) {
            hide($("profile-modal"));
            return;
        }

        if (!current) return setError(errorNode, "Enter your current password.");
        if (next.length < 8 || next.length > 128) {
            return setError(errorNode, "New password must be 8 to 128 characters.");
        }
        if (next !== confirm) return setError(errorNode, "Passwords do not match.");

        try {
            await post("/api/profile/password", { currentPassword: current, newPassword: next });
            hide($("profile-modal"));
            toast("Password updated.");
        } catch (error) {
            setError(errorNode, error.message || "Could not change the password.");
        }
    }

    /* ------------------------------------------------------------------ */
    /* Reports                                                            */
    /* ------------------------------------------------------------------ */

    function openReport(reportedUser, messageText) {
        state.report = { reportedUser, text: messageText };
        const reason = $("report-reason-input");
        if (reason) reason.value = "";
        show($("report-modal"));
        reason?.focus();
    }

    function closeReport() {
        state.report = null;
        hide($("report-modal"));
    }

    async function submitReport() {
        const reason = String($("report-reason-input")?.value || "").trim();

        if (!state.report || !state.room) return;

        if (!reason) {
            toast("Please describe the issue.");
            return;
        }

        try {
            await post("/api/reports", {
                room: state.room,
                reported_user: state.report.reportedUser,
                message_text: state.report.text.slice(0, MAX_TEXT),
                reason: reason.slice(0, 1000)
            });
            closeReport();
            toast("Report sent. Thank you.");
        } catch (error) {
            toast(error.message || "Could not send the report.");
        }
    }

    /* ------------------------------------------------------------------ */
    /* Admin panel                                                        */
    /* ------------------------------------------------------------------ */

    function adminRow() {
        const row = el("div", "bg-slate-900 border border-slate-700 rounded-lg p-2");
        Object.assign(row.style, {
            display: "flex",
            gap: "8px",
            alignItems: "center",
            justifyContent: "space-between"
        });
        return row;
    }

    function smallButton(label, tone) {
        const palette =
            tone === "danger"
                ? "bg-red-700 hover:bg-red-600 text-white"
                : tone === "success"
                    ? "bg-emerald-600 hover:bg-emerald-600 text-white"
                    : "bg-slate-700 hover:bg-slate-600 text-slate-300";

        const button = el(
            "button",
            `${palette} text-xs px-3 py-1.5 rounded-lg font-medium transition`,
            label
        );
        button.type = "button";
        return button;
    }

    function askBanDuration(username) {
        const answer = window.prompt(
            `Ban ${username} from #${state.room}.\n` +
            "Enter a number of days (1-365), or leave empty for a permanent ban.",
            "7"
        );

        if (answer === null) return undefined;          // cancelled

        const text = answer.trim();
        if (text === "") return null;                   // permanent

        const days = Number(text);
        if (!Number.isInteger(days) || days < 1 || days > 365) {
            toast("Enter a whole number between 1 and 365.");
            return undefined;
        }

        return days;
    }

    async function banFromRoom(username) {
        const days = askBanDuration(username);
        if (days === undefined) return false;

        try {
            await post(`/api/rooms/${encodeURIComponent(state.room)}/bans`, { username, days });
            toast(`${username} was banned from #${state.room}.`);
            return true;
        } catch (error) {
            toast(error.message || "Could not ban this user.");
            return false;
        }
    }

    async function openAdmin() {
        hide($("dropdown-menu"));
        if (!state.canManage || !state.room) return;

        const roomName = $("admin-room-name");
        if (roomName) roomName.textContent = "#" + state.room;

        show($("admin-modal"));
        await refreshAdmin();
    }

    async function refreshAdmin() {
        if (!state.canManage || !state.room) return;

        try {
            const data = await api(`/api/rooms/${encodeURIComponent(state.room)}/manage`);

            renderAdminMembers($("admin-members-list"), data?.members || [], data?.bans || []);
            renderAdminReports($("admin-reports-list"), data?.reports || [], data?.members || []);
        } catch (error) {
            toast(error.message || "Could not load the admin panel.");
        }
    }

    function renderAdminMembers(box, members, bans) {
        if (!box) return;

        const nodes = [];

        const manageable = members.filter(
            (m) => m.username !== state.user?.username && !m.isOwner && !m.isAdmin
        );

        if (!manageable.length) {
            nodes.push(el("p", "text-xs text-slate-400 italic", "No users to manage."));
        }

        manageable.forEach((member) => {
            const row = adminRow();
            row.appendChild(el("div", "text-xs text-slate-200", member.username));

            const ban = smallButton("Ban", "danger");
            on(ban, "click", async () => {
                if (await banFromRoom(member.username)) await refreshAdmin();
            });

            row.appendChild(ban);
            nodes.push(row);
        });

        if (bans.length) {
            nodes.push(el("div", "text-[11px] font-bold text-amber-300 mt-2", "Banned from this room"));

            bans.forEach((ban) => {
                const row = adminRow();
                const label = el("div", "text-xs text-slate-200", ban.username);
                label.appendChild(
                    el(
                        "div",
                        "text-[10px] text-red-400",
                        ban.expiresAt
                            ? `Until ${new Date(ban.expiresAt).toLocaleString()}`
                            : "Permanent"
                    )
                );

                const unban = smallButton("Unban");
                on(unban, "click", async () => {
                    try {
                        await api(
                            `/api/rooms/${encodeURIComponent(state.room)}/bans/${encodeURIComponent(ban.username)}`,
                            { method: "DELETE" }
                        );
                        toast(`${ban.username} can join #${state.room} again.`);
                        await refreshAdmin();
                    } catch (error) {
                        toast(error.message || "Could not unban this user.");
                    }
                });

                row.append(label, unban);
                nodes.push(row);
            });
        }

        box.replaceChildren(...nodes);
    }

    function renderAdminReports(box, reports, members) {
        if (!box) return;

        if (!reports.length) {
            box.replaceChildren(
                el("p", "text-xs text-slate-400 italic", "No reports submitted for this room.")
            );
            return;
        }

        const banTargets = new Set(
            members
                .filter((m) => m.username !== state.user?.username && !m.isOwner && !m.isAdmin)
                .map((m) => m.username)
        );

        box.replaceChildren(
            ...reports.map((report) => {
                const card = el("div", "bg-slate-900 border border-slate-700 rounded-lg p-3 space-y-2");

                card.appendChild(
                    el(
                        "div",
                        "text-xs text-slate-200",
                        `${report.reporter} reported ${report.reported_user || "a user"}`
                    )
                );
                card.appendChild(el("div", "text-xs text-slate-300 whitespace-pre-wrap", `Reason: ${report.reason}`));
                if (report.message_text) {
                    card.appendChild(
                        el("div", "text-[11px] text-slate-400 whitespace-pre-wrap", `Message: ${report.message_text}`)
                    );
                }

                const foot = el("div");
                Object.assign(foot.style, {
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    gap: "8px",
                    flexWrap: "wrap"
                });
                foot.appendChild(
                    el("span", "text-[10px] text-slate-500", `${report.status} - ${formatDateTime(report.created_at)}`)
                );

                if (report.status === "open") {
                    const actions = el("div");
                    Object.assign(actions.style, { display: "flex", gap: "6px" });

                    const resolve = (kind, label, tone) => {
                        const button = smallButton(label, tone);
                        on(button, "click", async () => {
                            try {
                                if (kind === "accept" && banTargets.has(report.reported_user)) {
                                    /* Accepting a report can also ban the user. */
                                    if (window.confirm(`Also ban ${report.reported_user} from this room?`)) {
                                        if (!(await banFromRoom(report.reported_user))) return;
                                    }
                                }

                                await post(
                                    `/api/rooms/${encodeURIComponent(state.room)}/reports/${encodeURIComponent(report.id)}/${kind}`,
                                    {}
                                );
                                await refreshAdmin();
                            } catch (error) {
                                toast(error.message || "Action failed.");
                            }
                        });
                        return button;
                    };

                    actions.append(resolve("accept", "Accept", "success"), resolve("dismiss", "Dismiss"));
                    foot.appendChild(actions);
                }

                card.appendChild(foot);
                return card;
            })
        );
    }

    async function deleteCurrentRoom() {
        if (!state.room || !state.canManage) return;

        const name = state.room;

        if (!window.confirm(`Permanently delete #${name} and all its messages?`)) return;

        try {
            await api(`/api/rooms/${encodeURIComponent(name)}`, { method: "DELETE" });
            hide($("admin-modal"));
            leaveRoom(true);
            toast(`#${name} was deleted.`);
        } catch (error) {
            toast(error.message || "Could not delete the room.");
        }
    }

    /* ------------------------------------------------------------------ */
    /* "Admin" tag shown when hovering an admin's avatar                  */
    /* ------------------------------------------------------------------ */

    function hideAdminTag() {
        state.adminTag?.remove();
        state.adminTag = null;
    }

    function showAdminTag(anchor) {
        hideAdminTag();

        const frame = el("div", "admin-tag");
        const pill = el("div", "admin-tag-pill");
        pill.appendChild(el("span", "admin-tag-text", "Admin"));
        frame.appendChild(pill);
        document.body.appendChild(frame);

        const a = anchor.getBoundingClientRect();
        const t = frame.getBoundingClientRect();

        let top = a.top - t.height - 8;
        if (top < 8) top = a.bottom + 8;

        const left = Math.max(
            8,
            Math.min(a.left + a.width / 2 - t.width / 2, window.innerWidth - t.width - 8)
        );

        frame.style.top = top + "px";
        frame.style.left = left + "px";

        requestAnimationFrame(() => frame.classList.add("visible"));
        state.adminTag = frame;
    }

    function wireAdminTag() {
        const chat = $("chat-messages");
        if (!chat) return;

        on(chat, "mouseover", (event) => {
            const anchor = event.target.closest?.("[data-admin]");
            if (anchor) showAdminTag(anchor);
        });

        on(chat, "mouseout", (event) => {
            const anchor = event.target.closest?.("[data-admin]");
            if (anchor && !anchor.contains(event.relatedTarget)) hideAdminTag();
        });

        on(chat, "scroll", hideAdminTag);
    }

    /* ------------------------------------------------------------------ */
    /* Events (birthday + holidays)                                       */
    /* ------------------------------------------------------------------ */

    // <events-pure>
    const EVENT_DEFS = [
        { name: "New Year", month: 1, day: 1 },
        { name: "Valentine's Day", month: 2, day: 14 },
        { name: "Halloween", month: 10, day: 31 },
        { name: "Christmas Eve", month: 12, day: 24 },
        { name: "Christmas Day", month: 12, day: 25 },
        { name: "New Year's Eve", month: 12, day: 31 }
    ];

    function easterDate(year) {
        /* Anonymous Gregorian algorithm */
        const a = year % 19;
        const b = Math.floor(year / 100);
        const c = year % 100;
        const d = Math.floor(b / 4);
        const e = b % 4;
        const f = Math.floor((b + 8) / 25);
        const g = Math.floor((b - f + 1) / 3);
        const h = (19 * a + b - d - g + 15) % 30;
        const i = Math.floor(c / 4);
        const k = c % 4;
        const l = (32 + 2 * e + 2 * i - h - k) % 7;
        const m = Math.floor((a + 11 * h + 22 * l) / 451);

        return {
            month: Math.floor((h + l - 7 * m + 114) / 31),
            day: ((h + l - 7 * m + 114) % 31) + 1
        };
    }

    function eventsForYear(year) {
        const easter = easterDate(year);

        return [...EVENT_DEFS, { name: "Easter Day", month: easter.month, day: easter.day }]
            .map((event) => ({ ...event, date: new Date(year, event.month - 1, event.day) }))
            .sort((x, y) => x.date - y.date);
    }

    function startOfDay(date) {
        return new Date(date.getFullYear(), date.getMonth(), date.getDate());
    }

    function daysBetween(from, to) {
        return Math.round((startOfDay(to) - startOfDay(from)) / 86400000);
    }

    function isLeapYear(year) {
        return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
    }

    function parseBirth(value) {
        const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value || ""));
        return match ? { year: +match[1], month: +match[2], day: +match[3] } : null;
    }

    function birthdayInYear(birth, year) {
        /* Feb 29 birthdays are celebrated on Feb 28 in non-leap years */
        const day = birth.month === 2 && birth.day === 29 && !isLeapYear(year) ? 28 : birth.day;
        return new Date(year, birth.month - 1, day);
    }

    function computeEventSummary(birthValue, username, now) {
        const today = startOfDay(now || new Date());
        const year = today.getFullYear();
        const greetings = [];
        const birth = parseBirth(birthValue);
        let nextBirthdayDays = null;

        if (birth) {
            const diff = daysBetween(today, birthdayInYear(birth, year));

            if (diff === 0) {
                greetings.push({
                    kind: "birthday",
                    text: `Happy Birthday, ${username}!`,
                    sub: `You are ${year - birth.year} today.`
                });
                nextBirthdayDays = 0;
            } else {
                nextBirthdayDays = diff > 0
                    ? diff
                    : daysBetween(today, birthdayInYear(birth, year + 1));
            }
        }

        const upcoming = [...eventsForYear(year), ...eventsForYear(year + 1)];

        upcoming
            .filter((event) => daysBetween(today, event.date) === 0)
            .forEach((event) => greetings.push({ kind: "event", text: `Happy ${event.name}!` }));

        const next = upcoming.find((event) => daysBetween(today, event.date) > 0) || null;

        return {
            greetings,
            next: next && { name: next.name, date: next.date, days: daysBetween(today, next.date) },
            nextBirthdayDays
        };
    }
    // </events-pure>

    function todayInputValue() {
        const now = new Date();
        const pad = (n) => String(n).padStart(2, "0");
        return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
    }

    function inDays(days) {
        if (days === 0) return "today";
        if (days === 1) return "tomorrow";
        return `in ${days} days`;
    }

    function renderEvents() {
        const form = $("events-birth-form");
        const body = $("events-body");
        const footer = $("events-footer");

        if (!body || !form) return;

        if (!state.birthDate) {
            show(form);
            hide(body);
            hide(footer);
            return;
        }

        hide(form);
        show(body);
        show(footer);

        const summary = computeEventSummary(state.birthDate, state.user?.username || "", new Date());
        const nodes = [];

        if (summary.greetings.length) {
            summary.greetings.forEach((greeting) => {
                const card = el("div", "event-card");
                card.appendChild(
                    el("div", "event-greeting", `${greeting.kind === "birthday" ? "🎂 " : "🎉 "}${greeting.text}`)
                );
                if (greeting.sub) card.appendChild(el("div", "event-sub", greeting.sub));
                nodes.push(card);
            });
        } else {
            const card = el("div", "event-card");
            card.appendChild(el("div", "event-sub", "No special event today."));
            nodes.push(card);
        }

        const lines = [];

        if (summary.next) {
            lines.push(
                `Next event: ${summary.next.name}, ${summary.next.date.toLocaleDateString(undefined, {
                    weekday: "long", month: "long", day: "numeric"
                })} (${inDays(summary.next.days)}).`
            );
        }

        if (summary.nextBirthdayDays !== null && summary.nextBirthdayDays > 0) {
            lines.push(`Your birthday is ${inDays(summary.nextBirthdayDays)}.`);
        }

        lines.forEach((line) => nodes.push(el("p", "text-xs text-slate-300", line)));

        body.replaceChildren(...nodes);
    }

    async function openEvents() {
        hide($("dropdown-menu"));
        setError($("events-error"), "");
        show($("events-modal"));

        if (state.birthDate === undefined) {
            try {
                const data = await api("/api/profile/birthdate");
                state.birthDate = data?.birthDate || null;
            } catch (error) {
                hide($("events-modal"));
                toast(error.message || "Could not load your events.");
                return;
            }
        }

        const input = $("events-birth-input");
        if (input) {
            input.max = todayInputValue();
            input.value = state.birthDate || "";
        }

        renderEvents();
    }

    async function saveBirthDate() {
        const input = $("events-birth-input");
        const errorNode = $("events-error");
        const value = String(input?.value || "");

        setError(errorNode, "");

        if (!/^\d{4}-\d{2}-\d{2}$/.test(value) || value < "1900-01-01" || value > todayInputValue()) {
            setError(errorNode, "Enter a valid birth date.");
            return;
        }

        try {
            await api("/api/profile/birthdate", {
                method: "PUT",
                body: JSON.stringify({ birthDate: value })
            });

            state.birthDate = value;
            renderEvents();
        } catch (error) {
            setError(errorNode, error.message || "Could not save your birth date.");
        }
    }

    function wireEvents() {
        const modal = $("events-modal");

        buttonsByText(modal, "✕").forEach((b) => on(b, "click", () => hide(modal)));
        buttonsByText(modal, "close").forEach((b) => on(b, "click", () => hide(modal)));

        on($("events-save-btn"), "click", saveBirthDate);

        on($("events-birth-input"), "keydown", (event) => {
            if (event.key === "Enter") { event.preventDefault(); saveBirthDate(); }
        });

        on($("events-change-btn"), "click", () => {
            const input = $("events-birth-input");
            setError($("events-error"), "");
            if (input) input.value = state.birthDate || "";
            show($("events-birth-form"));
            hide($("events-body"));
            hide($("events-footer"));
            input?.focus();
        });

        on($("events-cancel-btn"), "click", () => {
            if (state.birthDate) renderEvents(); else hide(modal);
        });
    }

    /* ------------------------------------------------------------------ */
    /* Wiring                                                             */
    /* ------------------------------------------------------------------ */

    function wireAuth() {
        on($("login-btn"), "click", () => submitAuth("login"));
        on($("create-btn"), "click", () => submitAuth("register"));
        on($("create-account-btn"), "click", showCreateForm);
        on($("back-to-login-btn"), "click", showLoginForm);

        [["login-username", "login-password"], ["login-password", "login-btn"],
         ["create-username", "create-password"], ["create-password", "create-btn"]
        ].forEach(([fromId, toId]) => {
            on($(fromId), "keydown", (event) => {
                if (event.key !== "Enter") return;
                event.preventDefault();
                const target = $(toId);
                if (target?.tagName === "BUTTON") target.click(); else target?.focus();
            });
        });
    }

    function wireRoom() {
        const modal = $("room-modal");
        on(buttonByText(modal, "exit"), "click", () => logout());
        on(buttonByText(modal, "join room"), "click", joinRoom);
        on($("room-name-input"), "keydown", (event) => {
            if (event.key === "Enter") { event.preventDefault(); joinRoom(); }
        });
    }

    function wireHeader() {
        on(buttonByText(document.querySelector("header"), "quit"), "click", () => leaveRoom(true));

        on($("current-user-display"), "click", (event) => {
            event.stopPropagation();
            const menu = $("dropdown-menu");
            if (!menu) return;
            menu.classList.add("flex");
            menu.classList.toggle("hidden");
        });

        const menu = $("dropdown-menu");
        const items = menu ? [...menu.children].filter((node) => node.textContent.trim()) : [];

        items.forEach((item) => {
            const label = item.textContent.trim().toLowerCase();

            if (label.includes("notification")) on(item, "click", openNotifications);
            else if (label.includes("profile")) on(item, "click", openProfile);
            else if (label.includes("admin")) on(item, "click", openAdmin);
            else if (label.includes("event")) on(item, "click", openEvents);
            else if (label.includes("log out")) on(item, "click", () => {
                hide(menu);
                logout();
            });
        });
    }

    function wireModals() {
        const closers = [
            ["notifications-modal", "notifications-modal"],
            ["profile-modal", "profile-modal"],
            ["admin-modal", "admin-modal"]
        ];

        closers.forEach(([modalId]) => {
            const modal = $(modalId);
            buttonsByText(modal, "✕").forEach((b) => on(b, "click", () => hide(modal)));
            buttonsByText(modal, "close").forEach((b) => on(b, "click", () => hide(modal)));
        });

        const profile = $("profile-modal");
        on(buttonByText(profile, "cancel"), "click", () => hide(profile));
        on(buttonByText(profile, "save changes"), "click", savePassword);

        on(buttonByText(profile, "take photo"), "click", () => openCamera("avatar"));
        on(buttonByText(profile, "upload photo"), "click", () => $("profile-avatar-input")?.click());
        on(buttonByText(profile, "remove"), "click", removeAvatar);
        on($("profile-avatar-input"), "change", handleAvatarFile);

        const note = [...profile.querySelectorAll("p")].find(
            (p) => p.textContent.includes("stored locally")
        );
        if (note) note.textContent = "Photos and animated GIFs (max 512 KB) are supported. Your avatar is stored on the server and visible to other users.";

        const report = $("report-modal");
        on(buttonByText(report, "cancel"), "click", closeReport);
        on(buttonByText(report, "submit report"), "click", submitReport);

        const admin = $("admin-modal");
        on(buttonByText(admin, "delete room"), "click", deleteCurrentRoom);

        const gif = $("gif-library-modal");
        buttonsByText(gif, "✕").forEach((b) => on(b, "click", closeGifLibrary));
        buttonsByText(gif, "close").forEach((b) => on(b, "click", closeGifLibrary));
        on($("gif-library-search"), "input", onGifSearchInput);

        const camera = $("camera-modal");
        buttonsByText(camera, "✕").forEach((b) => on(b, "click", closeCamera));
        on($("camera-photo-btn"), "click", () => setCameraMode("photo"));
        on($("camera-video-btn"), "click", () => setCameraMode("video"));
        on($("camera-action-btn"), "click", onCameraAction);

        document.addEventListener("keydown", (event) => {
            if (event.key !== "Escape") return;
            ["notifications-modal", "profile-modal", "admin-modal", "events-modal"].forEach((id) => hide($(id)));
            closeGifLibrary();
            closeReport();
            closeUploadMenu();
            hide($("dropdown-menu"));
            if (!$("camera-modal")?.classList.contains("hidden")) closeCamera();
        });
    }

    function wireComposer() {
        on($("send-btn"), "click", sendTypedMessage);

        const input = $("message-input");
        on(input, "keydown", (event) => {
            if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
                event.preventDefault();
                sendTypedMessage();
            }
        });
        on(input, "input", autoGrowInput);

        on($("gif-btn"), "click", openGifLibrary);
        on($("camera-btn"), "click", () => openCamera("message"));
        on($("record-btn"), "click", toggleVoiceRecording);

        on($("upload-btn"), "click", (event) => {
            event.stopPropagation();
            toggleUploadMenu();
        });

        const menu = $("upload-menu");
        const options = menu ? [...menu.querySelectorAll("button")] : [];
        on(options[0], "click", () => pickFile("image"));
        on(options[1], "click", () => pickFile("video"));

        on($("upload-input"), "change", handleUploadChange);
    }

    function wireGlobal() {
        document.addEventListener("click", (event) => {
            const menu = $("dropdown-menu");
            const container = $("user-dropdown-container");
            if (menu && !menu.classList.contains("hidden") && !container?.contains(event.target)) {
                hide(menu);
            }

            const upload = $("upload-menu");
            const wrapper = $("upload-wrapper");
            if (upload?.classList.contains("visible") && !wrapper?.contains(event.target)) {
                closeUploadMenu();
            }
        });

        window.addEventListener("beforeunload", () => {
            state.closingSocket = true;
            try { state.socket?.close(); } catch (_) {}
        });
    }

    /* ------------------------------------------------------------------ */
    /* Start                                                              */
    /* ------------------------------------------------------------------ */

    async function init() {
        show($("loading-screen"));

        let me = null;

        try {
            await loadCsrf();
            me = await api("/api/me");
        } catch (_) {
            me = null;
        }

        hide($("loading-screen"));

        if (me?.authenticated && !me.banned) {
            await onAuthenticated(me);
        } else if (me?.banned) {
            await logout(me.banMessage || "Your account is banned.");
        } else {
            showAuth();
        }
    }

    function start() {
        wireAuth();
        wireRoom();
        wireHeader();
        wireModals();
        wireComposer();
        wireAdminTag();
        wireEvents();
        wireGlobal();
        init();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", start, { once: true });
    } else {
        start();
    }
})();