
(() => {
    "use strict";

    const TABS = ["overview", "users", "rooms", "reports", "notify"];
    const MAX_IMAGE_BYTES = 2 * 1024 * 1024;
    const MAX_IMAGE_SIDE = 1280;
    const MAX_TEXT = 1000;
    const REFRESH_MS = 30000;

    const AVATAR_COLORS = [
        "bg-amber-600", "bg-blue-600", "bg-emerald-600", "bg-cyan-600",
        "bg-pink-600", "bg-purple-600", "bg-orange-600", "bg-yellow-600",
        "bg-brown-600", "bg-beige-600", "bg-emerald-700"
    ];

    const state = {
        csrf: "",
        me: null,
        tab: "overview",
        stats: null,
        users: [],
        rooms: [],
        reports: [],
        userSearch: "",
        userFilter: "all", 
        roomSearch: "",
        reportFilter: "open",
        notify: { target: "all", username: "", room: "", text: "", file: null, previewUrl: "", sending: false },
        renderedTab: null,
        timer: null
    };

    const $ = (id) => document.getElementById(id);

    function show(node) { node?.classList.remove("hidden"); }
    function hide(node) { node?.classList.add("hidden"); }

    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = String(text);
        return node;
    }

    function on(node, eventName, handler) {
        node?.addEventListener(eventName, handler);
    }

    function plural(count, word) {
        return `${count} ${word}${count === 1 ? "" : "s"}`;
    }

    function formatDate(value) {
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? "" : date.toLocaleDateString();
    }

    function formatDateTime(value) {
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? "" : date.toLocaleString();
    }

    function isBanned(user) {
        return Boolean(user.banned_until) && new Date(user.banned_until).getTime() > Date.now();
    }

    function toast(message) {
        const node = el("div", "admin-toast", message);
        document.body.appendChild(node);
        setTimeout(() => node.remove(), 3500);
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

        const data = response.status === 204 ? null : await response.json().catch(() => null);

        if (!response.ok) {
            if (response.status === 403 && data?.error === "Invalid CSRF token." && !retried) {
                await loadCsrf();
                return api(path, options, true);
            }

            if (response.status === 401) {
                window.location.replace("/");
            }

            const error = new Error(
                response.status === 429
                    ? "Too many requests. Please wait a moment and try again."
                    : data?.error || `Request failed (${response.status}).`
            );
            error.status = response.status;
            throw error;
        }

        return data;
    }

    function post(path, body) {
        return api(path, { method: "POST", body: JSON.stringify(body ?? {}) });
    }

    /* ------------------------------------------------------------------ */
    /* Small UI pieces                                                    */
    /* ------------------------------------------------------------------ */

    function avatarColorClass(username) {
        let hash = 0;
        for (const ch of String(username)) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
        return AVATAR_COLORS[hash % AVATAR_COLORS.length];
    }

    function makeAvatar(username, size) {
        const ring = el("span", "avatar-ring bg-gradient-to-r from-blue-600 via-red-500 to-yellow-400 rounded-full shrink-0");
        const circle = el("span", `avatar-circle ${avatarColorClass(username)} rounded-full text-white font-bold`);

        circle.style.width = size + "px";
        circle.style.height = size + "px";
        circle.style.fontSize = Math.max(9, Math.round(size * 0.5)) + "px";
        circle.textContent = (username || "?")[0].toUpperCase();

        const img = el("img");
        img.alt = "";
        on(img, "load", () => { circle.textContent = ""; circle.appendChild(img); });
        on(img, "error", () => img.remove());
        img.src = `/api/avatars/${encodeURIComponent(username)}`;

        ring.appendChild(circle);
        return ring;
    }

    function adminBadge() {
        return el("span", "admin-badge", "Admin");
    }

    function tag(text, kind) {
        return el("span", "dash-tag" + (kind ? ` dash-tag-${kind}` : ""), text);
    }

    function button(label, tone) {
        const palette =
            tone === "danger"
                ? "bg-red-700 hover:bg-red-600 text-white"
                : "bg-slate-700 hover:bg-slate-600 text-slate-300";

        const node = el("button", `${palette} text-xs px-3 py-1.5 rounded-lg font-medium transition`, label);
        node.type = "button";
        return node;
    }

    function pill(label, active, onClick) {
        const node = el("button", "dash-tab" + (active ? " active" : ""), label);
        node.type = "button";
        on(node, "click", onClick);
        return node;
    }

    function empty(text) {
        return el("p", "text-xs text-slate-400 italic", text);
    }

    function setBadge(host, count) {
        host?.querySelector(":scope > [data-count-badge]")?.remove();

        if (host && count > 0) {
            const badge = el("span", "count-badge", count > 99 ? "99+" : String(count));
            badge.dataset.countBadge = "1";
            host.appendChild(badge);
        }
    }

    /* ------------------------------------------------------------------ */
    /* Data                                                               */
    /* ------------------------------------------------------------------ */

    async function loadAll(quiet) {
        const main = $("admin-main");

        if (!quiet && main) main.replaceChildren(empty("Loading..."));

        try {
            const [stats, users, rooms, reports] = await Promise.all([
                api("/api/admin/stats"),
                api("/api/admin/users"),
                api("/api/admin/rooms"),
                api("/api/admin/reports")
            ]);

            state.stats = stats;
            state.users = users?.users || [];
            state.rooms = rooms?.rooms || [];
            state.reports = reports?.reports || [];

            render();
        } catch (error) {
            if (!quiet && main) main.replaceChildren(empty(error.message || "Could not load the data."));
        }
    }

    async function act(request, successMessage) {
        try {
            await request();
            if (successMessage) toast(successMessage);
            await loadAll(true);
            return true;
        } catch (error) {
            toast(error.message || "Action failed.");
            return false;
        }
    }

    function openReportCount() {
        return state.reports.filter((r) => r.status === "open").length;
    }

    /* ------------------------------------------------------------------ */
    /* Actions                                                            */
    /* ------------------------------------------------------------------ */

    function banUser(username) {
        const answer = window.prompt(`Ban ${username} from SY Chat for how many days? (1-30)`, "7");
        if (answer === null) return Promise.resolve(false);

        const days = Number(answer.trim());

        if (!Number.isInteger(days) || days < 1 || days > 30) {
            toast("Enter a whole number between 1 and 30.");
            return Promise.resolve(false);
        }

        return act(
            () => post("/api/admin/ban", { username, days }),
            `${username} was banned for ${plural(days, "day")}.`
        );
    }

    function unbanUser(username) {
        return act(
            () => post(`/api/admin/users/${encodeURIComponent(username)}/unban`, {}),
            `${username} was unbanned.`
        );
    }

    function toggleAdmin(user) {
        const verb = user.is_admin ? "Remove administrator access from" : "Give administrator access to";
        if (!window.confirm(`${verb} ${user.username}?`)) return Promise.resolve(false);

        return act(
            () => post(`/api/admin/users/${encodeURIComponent(user.username)}/admin`, { isAdmin: !user.is_admin }),
            user.is_admin ? `${user.username} is no longer an admin.` : `${user.username} is now an admin.`
        );
    }

    function deleteRoom(room) {
        if (!window.confirm(`Permanently delete #${room.name} and all its messages?`)) {
            return Promise.resolve(false);
        }

        return act(
            () => api(`/api/admin/rooms/${encodeURIComponent(room.name)}`, { method: "DELETE" }),
            `#${room.name} was deleted.`
        );
    }

    function resolveReport(report, kind) {
        return act(
            () => post(`/api/admin/reports/${encodeURIComponent(report.id)}/${kind}`, {}),
            kind === "accept" ? "Report accepted." : "Report dismissed."
        );
    }

    /* ------------------------------------------------------------------ */
    /* Rendering                                                          */
    /* ------------------------------------------------------------------ */

    function renderNav() {
        TABS.forEach((name) => {
            const item = $(`admin-nav-${name}`);
            item?.classList.toggle("active", state.tab === name);
        });

        setBadge($("admin-nav-reports"), openReportCount());
    }

    function render(options = {}) {
        renderNav();

        const main = $("admin-main");
        if (!main) return;

        const refresh = !options.force && state.renderedTab === state.tab;

        /* Background refresh: never wipe the form or a field being typed in. */
        if (refresh) {
            const active = document.activeElement;
            const typing = active && main.contains(active) && ["INPUT", "TEXTAREA", "SELECT"].includes(active.tagName);
            if (state.tab === "notify" || typing) return;
        }

        state.renderedTab = state.tab;

        switch (state.tab) {
            case "notify": return renderNotify(main);
            case "users": return renderUsers(main);
            case "rooms": return renderRooms(main);
            case "reports": return renderReports(main);
            default: return renderOverview(main);
        }
    }

    function section(title, subtitle) {
        const head = el("div", "admin-section-head");
        head.appendChild(el("h2", "admin-section-title", title));
        if (subtitle) head.appendChild(el("p", "dash-meta", subtitle));
        return head;
    }

    /* ---- Overview ---- */

    function renderOverview(main) {
        const stats = state.stats || {};

        const cards = [
            ["Users", stats.users],
            ["Online now", stats.online_users],
            ["Rooms", stats.rooms],
            ["Messages", stats.messages],
            ["Messages (24h)", stats.messages_today],
            ["Open reports", stats.open_reports],
            ["Banned users", stats.banned_users],
            ["Admins", stats.admins]
        ];

        const grid = el("div", "stat-grid");

        cards.forEach(([label, value]) => {
            const card = el("div", "stat-card");
            card.appendChild(el("div", "stat-value", Number(value ?? 0).toLocaleString()));
            card.appendChild(el("div", "stat-label", label));
            grid.appendChild(card);
        });

        const panels = el("div", "admin-panels");

        /* Open reports */
        const reportsCard = el("div", "admin-card");
        reportsCard.appendChild(el("h3", "admin-card-title", "Open reports"));
        const open = state.reports.filter((r) => r.status === "open").slice(0, 5);

        if (!open.length) {
            reportsCard.appendChild(empty("Nothing waiting for you."));
        } else {
            open.forEach((report) => {
                const row = el("div", "admin-mini-row");
                const info = el("div", "dash-main");
                info.appendChild(el("div", "text-xs text-slate-200", `${report.reporter} reported ${report.reported_user || "a user"}`));
                info.appendChild(el("div", "dash-meta", `#${report.room} · ${report.reason}`));

                const actions = el("div", "dash-actions");
                const accept = button("Accept", "danger");
                const dismiss = button("Dismiss");
                on(accept, "click", () => resolveReport(report, "accept"));
                on(dismiss, "click", () => resolveReport(report, "dismiss"));
                actions.append(accept, dismiss);

                row.append(info, actions);
                reportsCard.appendChild(row);
            });
        }

        /* Busiest rooms */
        const roomsCard = el("div", "admin-card");
        roomsCard.appendChild(el("h3", "admin-card-title", "Busiest rooms"));
        const busiest = [...state.rooms].sort((a, b) => b.messages - a.messages).slice(0, 5);

        if (!busiest.length) {
            roomsCard.appendChild(empty("No rooms yet."));
        } else {
            busiest.forEach((room) => {
                const row = el("div", "admin-mini-row");
                const info = el("div", "dash-main");
                info.appendChild(el("div", "text-xs text-slate-200", `#${room.name}`));
                info.appendChild(el("div", "dash-meta", `${plural(room.members, "member")} · ${room.online} online`));
                row.append(info, tag(plural(room.messages, "message")));
                roomsCard.appendChild(row);
            });
        }

        /* Newest users */
        const usersCard = el("div", "admin-card");
        usersCard.appendChild(el("h3", "admin-card-title", "Newest users"));
        const newest = [...state.users]
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
            .slice(0, 5);

        if (!newest.length) {
            usersCard.appendChild(empty("No users yet."));
        } else {
            newest.forEach((user) => {
                const row = el("div", "admin-mini-row");
                const info = el("div", "dash-title");
                info.append(makeAvatar(user.username, 22), el("span", "", user.username));
                if (user.is_admin) info.appendChild(adminBadge());
                row.append(info, el("span", "dash-meta", formatDate(user.created_at)));
                usersCard.appendChild(row);
            });
        }

        panels.append(reportsCard, roomsCard, usersCard);

        main.replaceChildren(section("Overview", "Live numbers for the whole site. Refreshes every 30 seconds."), grid, panels);
    }

    /* ---- Users ---- */

    function renderUsers(main) {
        const toolbar = el("div", "admin-toolbar");

        const search = el("input", "dash-search");
        search.type = "search";
        search.placeholder = "Search users...";
        search.autocomplete = "off";
        search.value = state.userSearch;

        const filters = el("div", "admin-filters");
        const body = el("div", "admin-table-wrap");

        const drawFilters = () => {
            filters.replaceChildren(
                ...[["all", "All"], ["admins", "Admins"], ["banned", "Banned"]].map(([key, label]) =>
                    pill(label, state.userFilter === key, () => {
                        state.userFilter = key;
                        drawFilters();
                        drawRows();
                    })
                )
            );
        };

        const drawRows = () => {
            const query = state.userSearch.trim().toLowerCase();

            const users = state.users.filter((u) => {
                if (query && !u.username.toLowerCase().includes(query)) return false;
                if (state.userFilter === "admins") return u.is_admin;
                if (state.userFilter === "banned") return isBanned(u);
                return true;
            });

            body.replaceChildren(users.length ? usersTable(users) : empty("No users found."));
        };

        on(search, "input", () => {
            state.userSearch = search.value;
            drawRows();
        });

        toolbar.append(search, filters);
        main.replaceChildren(
            section("Users", `${plural(state.users.length, "account")} on SY Chat.`),
            toolbar,
            body
        );

        drawFilters();
        drawRows();
    }

    function usersTable(users) {
        const table = el("table", "admin-table");
        const head = el("tr");
        ["User", "Status", "Joined", "Messages", "Rooms owned", ""].forEach((label) => head.appendChild(el("th", "", label)));
        table.appendChild(el("thead")).appendChild(head);

        const tbody = el("tbody");

        users.forEach((user) => {
            const me = user.username === state.me?.username;
            const banned = isBanned(user);
            const row = el("tr");

            const name = el("td");
            const title = el("div", "dash-title");
            title.append(makeAvatar(user.username, 26), el("span", "", user.username));
            if (user.is_admin) title.appendChild(adminBadge());
            if (me) title.appendChild(tag("You"));
            name.appendChild(title);

            const status = el("td");
            if (banned) {
                status.appendChild(tag("Banned", "danger"));
                status.appendChild(el("div", "dash-meta", `until ${formatDateTime(user.banned_until)}`));
            } else {
                status.appendChild(tag("Active", "live"));
            }

            const actions = el("td", "admin-actions-cell");
            const group = el("div", "dash-actions");

            if (!me) {
                if (banned) {
                    const unban = button("Unban");
                    on(unban, "click", () => unbanUser(user.username));
                    group.appendChild(unban);
                } else if (!user.is_admin) {
                    const ban = button("Ban", "danger");
                    on(ban, "click", () => banUser(user.username));
                    group.appendChild(ban);
                }

                const role = button(user.is_admin ? "Remove admin" : "Make admin");
                on(role, "click", () => toggleAdmin(user));
                group.appendChild(role);
            }

            actions.appendChild(group);

            row.append(
                name,
                status,
                el("td", "", formatDate(user.created_at)),
                el("td", "", Number(user.message_count ?? 0).toLocaleString()),
                el("td", "", user.owned_rooms ?? 0),
                actions
            );
            tbody.appendChild(row);
        });

        table.appendChild(tbody);
        return table;
    }

    /* ---- Rooms ---- */

    function renderRooms(main) {
        const toolbar = el("div", "admin-toolbar");

        const search = el("input", "dash-search");
        search.type = "search";
        search.placeholder = "Search rooms...";
        search.autocomplete = "off";
        search.value = state.roomSearch;

        const body = el("div", "admin-table-wrap");

        const drawRows = () => {
            const query = state.roomSearch.trim().toLowerCase();
            const rooms = state.rooms.filter((r) => !query || r.name.toLowerCase().includes(query));
            body.replaceChildren(rooms.length ? roomsTable(rooms) : empty("No rooms found."));
        };

        on(search, "input", () => {
            state.roomSearch = search.value;
            drawRows();
        });

        toolbar.appendChild(search);
        main.replaceChildren(
            section("Rooms", `${plural(state.rooms.length, "room")} created so far.`),
            toolbar,
            body
        );
        drawRows();
    }

    function roomsTable(rooms) {
        const table = el("table", "admin-table");
        const head = el("tr");
        ["Room", "Owner", "Members", "Online", "Messages", "Reports", "Created", ""].forEach((label) => head.appendChild(el("th", "", label)));
        table.appendChild(el("thead")).appendChild(head);

        const tbody = el("tbody");

        rooms.forEach((room) => {
            const row = el("tr");

            const name = el("td");
            name.appendChild(el("div", "dash-title", `#${room.name}`));

            const reports = el("td");
            reports.appendChild(room.open_reports > 0 ? tag(String(room.open_reports), "danger") : el("span", "dash-meta", "0"));

            const online = el("td");
            online.appendChild(room.online > 0 ? tag(String(room.online), "live") : el("span", "dash-meta", "0"));

            const actions = el("td", "admin-actions-cell");
            const remove = button("Delete", "danger");
            on(remove, "click", () => deleteRoom(room));
            const group = el("div", "dash-actions");
            group.appendChild(remove);
            actions.appendChild(group);

            row.append(
                name,
                el("td", "", room.owner || "-"),
                el("td", "", room.members),
                online,
                el("td", "", Number(room.messages).toLocaleString()),
                reports,
                el("td", "", formatDate(room.created_at)),
                actions
            );
            tbody.appendChild(row);
        });

        table.appendChild(tbody);
        return table;
    }

    /* ---- Notify (text + optional image) ---- */

    function toBlob(canvas, type, quality) {
        return new Promise((resolve) => canvas.toBlob(resolve, type, quality));
    }

    async function prepareImage(file) {
        if (!/^image\/(png|jpe?g|gif|webp)$/i.test(file.type)) {
            throw new Error("Use a PNG, JPEG, WebP or GIF image.");
        }

        if (file.type === "image/gif") {
            if (file.size > MAX_IMAGE_BYTES) throw new Error("GIF is too large (max 2 MB).");
            return file;
        }

        const bitmap = await createImageBitmap(file);
        const scale = Math.min(1, MAX_IMAGE_SIDE / Math.max(bitmap.width, bitmap.height));

        const canvas = document.createElement("canvas");
        canvas.width = Math.max(1, Math.round(bitmap.width * scale));
        canvas.height = Math.max(1, Math.round(bitmap.height * scale));
        canvas.getContext("2d").drawImage(bitmap, 0, 0, canvas.width, canvas.height);

        let blob = await toBlob(canvas, "image/webp", 0.85);
        if (!blob || blob.type !== "image/webp") blob = await toBlob(canvas, "image/jpeg", 0.88);

        if (!blob || blob.size > MAX_IMAGE_BYTES) throw new Error("Image is too large even after resizing.");

        return blob;
    }

    function setNotifyImage(blob) {
        const form = state.notify;

        if (form.previewUrl) URL.revokeObjectURL(form.previewUrl);

        form.file = blob || null;
        form.previewUrl = blob ? URL.createObjectURL(blob) : "";
    }

    function notifyLabel(text) {
        return el("label", "admin-label", text);
    }

    function renderNotify(main) {
        const form = state.notify;

        const wrapper = el("div", "admin-form-grid");
        const left = el("div", "admin-form");
        const right = el("div", "admin-form");

        /* --- Recipients --- */
        left.appendChild(notifyLabel("Send to"));

        const targets = el("div", "admin-filters");
        const targetField = el("div", "admin-field");

        const drawTargets = () => {
            targets.replaceChildren(
                ...[["all", "All users"], ["user", "One user"], ["room", "A room's members"]].map(([key, label]) =>
                    pill(label, form.target === key, () => {
                        form.target = key;
                        drawTargets();
                        drawTargetField();
                    })
                )
            );
        };

        const drawTargetField = () => {
            if (form.target === "user") {
                const input = el("input", "dash-search");
                input.type = "text";
                input.placeholder = "Username";
                input.autocomplete = "off";
                input.value = form.username;
                input.setAttribute("list", "admin-user-list");

                const list = el("datalist");
                list.id = "admin-user-list";
                state.users.forEach((u) => {
                    const option = el("option");
                    option.value = u.username;
                    list.appendChild(option);
                });

                on(input, "input", () => { form.username = input.value; });
                targetField.replaceChildren(input, list);
            } else if (form.target === "room") {
                const select = el("select", "admin-select");

                if (!state.rooms.length) {
                    select.appendChild(el("option", "", "No rooms yet"));
                } else {
                    state.rooms.forEach((room) => {
                        const option = el("option", "", `#${room.name} (${plural(room.members, "member")})`);
                        option.value = room.name;
                        select.appendChild(option);
                    });

                    if (!form.room || !state.rooms.some((r) => r.name === form.room)) form.room = state.rooms[0].name;
                    select.value = form.room;
                }

                on(select, "change", () => { form.room = select.value; });
                targetField.replaceChildren(select);
            } else {
                targetField.replaceChildren(
                    el("p", "admin-hint", `Every account (${plural(state.users.length, "user")}) will receive it.`)
                );
            }
        };

        left.append(targets, targetField);

        /* --- Message --- */
        left.appendChild(notifyLabel("Message"));

        const textarea = el("textarea", "admin-textarea");
        textarea.rows = 5;
        textarea.maxLength = MAX_TEXT;
        textarea.placeholder = "Write the message users will see next to the image...";
        textarea.value = form.text;

        const counter = el("div", "admin-hint admin-counter", `${form.text.length} / ${MAX_TEXT}`);

        left.append(textarea, counter);

        /* --- Image --- */
        left.appendChild(notifyLabel("Image (optional)"));

        const fileInput = el("input");
        fileInput.type = "file";
        fileInput.accept = "image/png,image/jpeg,image/gif,image/webp";
        fileInput.className = "hidden";

        const choose = button("Choose image");
        const remove = button("Remove image");
        const imageRow = el("div", "dash-actions");
        imageRow.append(choose, remove, fileInput);

        left.appendChild(imageRow);
        left.appendChild(el("p", "admin-hint", "PNG, JPEG, WebP or GIF, up to 2 MB. Large photos are resized automatically."));

        /* --- Send --- */
        const send = el("button", "admin-send-btn", "Send notification");
        send.type = "button";
        left.appendChild(send);

        /* --- Live preview --- */
        right.appendChild(notifyLabel("Preview"));

        const previewCard = el("div", "notif-card bg-slate-900 border border-slate-700 rounded-lg p-3");
        right.appendChild(previewCard);
        right.appendChild(el("p", "admin-hint", "This is how it will look in the user's Notifications window."));

        const drawPreview = () => {
            previewCard.replaceChildren();

            if (form.previewUrl) {
                const image = el("img", "notif-image");
                image.src = form.previewUrl;
                image.alt = "";
                previewCard.appendChild(image);
            }

            const body = el("div", "notif-body");
            body.appendChild(
                form.text.trim()
                    ? el("div", "notif-text text-xs text-slate-200", form.text)
                    : el("div", "text-xs text-slate-500 italic", "Your message will appear here.")
            );
            body.appendChild(el("div", "text-[10px] text-slate-500", "just now"));
            previewCard.appendChild(body);

            remove.classList.toggle("hidden", !form.file);
        };

        on(textarea, "input", () => {
            form.text = textarea.value;
            counter.textContent = `${form.text.length} / ${MAX_TEXT}`;
            drawPreview();
        });

        on(choose, "click", () => fileInput.click());

        on(fileInput, "change", async () => {
            const file = fileInput.files?.[0];
            fileInput.value = "";
            if (!file) return;

            try {
                setNotifyImage(await prepareImage(file));
                drawPreview();
            } catch (error) {
                toast(error.message || "Could not use this image.");
            }
        });

        on(remove, "click", () => {
            setNotifyImage(null);
            drawPreview();
        });

        on(send, "click", async () => {
            if (form.sending) return;

            const text = form.text.trim();
            let target;

            if (!text) return toast("Write a message first.");

            if (form.target === "user") {
                const username = form.username.trim();
                const known = state.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
                if (!known) return toast("Choose an existing username.");
                target = { type: "user", username: known.username };
            } else if (form.target === "room") {
                if (!form.room) return toast("Choose a room.");
                target = { type: "room", room: form.room };
            } else {
                target = { type: "all" };
            }

            const where =
                target.type === "all" ? `all ${plural(state.users.length, "user")}`
                : target.type === "room" ? `the members of #${target.room}`
                : target.username;

            if (!window.confirm(`Send this notification to ${where}?`)) return;

            form.sending = true;
            send.disabled = true;
            send.textContent = "Sending...";

            try {
                let imageId = null;

                if (form.file) {
                    const uploaded = await api("/api/admin/notification-images", {
                        method: "PUT",
                        headers: { "Content-Type": form.file.type },
                        body: form.file
                    });
                    imageId = uploaded?.imageId ?? null;
                }

                const result = await post("/api/admin/notifications", { text, imageId, target });

                toast(`Sent to ${plural(result?.recipients ?? 0, "user")}.`);

                form.text = "";
                setNotifyImage(null);
                form.sending = false;
                render({ force: true });
            } catch (error) {
                toast(error.message || "Could not send the notification.");
                form.sending = false;
                send.disabled = false;
                send.textContent = "Send notification";
            }
        });

        wrapper.append(left, right);

        main.replaceChildren(
            section("Notify", "Send a notification, with an optional image, to everyone, one user or a whole room."),
            wrapper
        );

        drawTargets();
        drawTargetField();
        drawPreview();
    }

    /* ---- Reports ---- */

    function renderReports(main) {
        const filters = el("div", "admin-filters");
        const list = el("div", "dash-list");

        const drawFilters = () => {
            filters.replaceChildren(
                ...[["open", "Open"], ["all", "All"]].map(([key, label]) =>
                    pill(label, state.reportFilter === key, () => {
                        state.reportFilter = key;
                        drawFilters();
                        drawList();
                    })
                )
            );
        };

        const drawList = () => {
            const reports = state.reports
                .filter((r) => state.reportFilter === "all" || r.status === "open")
                .slice(0, 200);

            list.replaceChildren(
                ...(reports.length
                    ? reports.map(reportCard)
                    : [empty(state.reportFilter === "open" ? "No open reports. Nice and quiet." : "No reports yet.")])
            );
        };

        const toolbar = el("div", "admin-toolbar");
        toolbar.appendChild(filters);

        main.replaceChildren(
            section("Reports", `${plural(openReportCount(), "open report")} across all rooms.`),
            toolbar,
            list
        );

        drawFilters();
        drawList();
    }

    function reportCard(report) {
        const card = el("div", "dash-card");

        const head = el("div", "dash-title");
        head.append(
            el("span", "", `${report.reporter} reported ${report.reported_user || "a user"}`),
            tag(`#${report.room}`),
            tag(report.status, report.status === "open" ? "danger" : "")
        );
        card.appendChild(head);

        card.appendChild(el("div", "text-xs text-slate-300 whitespace-pre-wrap", `Reason: ${report.reason}`));

        if (report.message_text) {
            card.appendChild(el("div", "dash-meta whitespace-pre-wrap", `Message: ${report.message_text}`));
        }

        const foot = el("div", "dash-foot-row");
        foot.appendChild(el("span", "dash-meta", formatDateTime(report.created_at)));

        if (report.status === "open") {
            const actions = el("div", "dash-actions");

            const accept = button("Accept", "danger");
            const dismiss = button("Dismiss");
            on(accept, "click", () => resolveReport(report, "accept"));
            on(dismiss, "click", () => resolveReport(report, "dismiss"));
            actions.append(accept, dismiss);

            const target = state.users.find((u) => u.username === report.reported_user);

            if (target && !target.is_admin && !isBanned(target) && target.username !== state.me?.username) {
                const ban = button("Ban user", "danger");
                on(ban, "click", () => banUser(target.username));
                actions.appendChild(ban);
            }

            foot.appendChild(actions);
        }

        card.appendChild(foot);
        return card;
    }

    function wire() {
        TABS.forEach((name) => on($(`admin-nav-${name}`), "click", () => {
            state.tab = name;
            render({ force: true });
        }));

        on($("admin-logout"), "click", async () => {
            try { await post("/api/auth/logout", {}); } catch (_) {}
            window.location.assign("/");
        });
    }

    async function init() {
        let me = null;

        try {
            await loadCsrf();
            me = await api("/api/me");
        } catch (_) {
            window.location.replace("/");
            return;
        }

        if (!me?.authenticated) {
            window.location.replace("/");
            return;
        }

        if (!me.isAdmin) {
            show($("admin-denied"));
            $("admin-logout")?.classList.add("hidden");
            return;
        }

        state.me = { username: me.username };

        const user = $("admin-user");
        if (user) user.replaceChildren(makeAvatar(me.username, 22), el("span", "", me.username), adminBadge());

        show($("admin-layout"));
        wire();
        await loadAll(false);

        state.timer = setInterval(() => {
            if (!document.hidden) loadAll(true);
        }, REFRESH_MS);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init, { once: true });
    } else {
        init();
    }
})();