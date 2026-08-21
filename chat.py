from dataclasses import dataclass
import flet as ft
import sqlite3
import random

@dataclass
class Message:
    user_name: str
    text: str
    message_type: str

class ChatMessage(ft.Row):
    def __init__(self, message: Message):
        super().__init__()
        self.message = message
        self.vertical_alignment = ft.CrossAxisAlignment.START
        self.controls = [
            ft.CircleAvatar(
                content=ft.Text(self.get_initials(self.message.user_name)),
                color=ft.Colors.WHITE,
                bgcolor=self.get_avatar_color(self.message.user_name),
            ),
            ft.Column(
                tight=True,
                spacing=5,
                controls=[
                    ft.Text(self.message.user_name, weight=ft.FontWeight.BOLD),
                    ft.Text(self.message.text, selectable=True),
                ],
            ),
        ]

    def get_initials(self, user_name: str):
        return user_name[:2].capitalize() if user_name else "??"

    def get_avatar_color(self, user_name: str):
        colors_lookup = [
            ft.Colors.AMBER, ft.Colors.BLUE, ft.Colors.BROWN, ft.Colors.CYAN,
            ft.Colors.GREEN, ft.Colors.INDIGO, ft.Colors.LIME, ft.Colors.ORANGE,
            ft.Colors.PINK, ft.Colors.PURPLE, ft.Colors.RED, ft.Colors.TEAL, ft.Colors.YELLOW,
        ]
        return colors_lookup[hash(user_name) % len(colors_lookup)]

DB_NAME = 'sychat.db'

def get_db_connection():
    return sqlite3.connect(DB_NAME, check_same_thread=False)

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()

def main(page: ft.Page):
    page.horizontal_alignment = ft.CrossAxisAlignment.STRETCH
    page.title = "SY Chat"
    page.icon = "ChatLogo.png"
    init_db()

    def clear_errors(e):
        if e.control.error_style:
            e.control.error_text = None
            page.update()

    def update_suggested_username(e):
        clear_errors(e)
        n1 = reg_firstname.value.strip()
        n2 = reg_lastname.value.strip()
        if n1 or n2:
            combine = (n1 + n2).capitalize()
            num = random.randint(100, 999)
            reg_username.hint_text = f"Ex: {combine}{num}"
        else:
            reg_username.hint_text = "Ex: SiguiYohan123"
        page.update()

    def open_create(e):
        welcome_dlg.open = False
        create_dlg.open = True
        page.update()

    def join_sychat(e):
        f_name = reg_firstname.value.strip()
        l_name = reg_lastname.value.strip()
        username = reg_username.value.strip()
        password = reg_password.value.strip()
        create_dlg.open = False
        welcome_dlg.open = True
        is_valid = True

        if not f_name:
            reg_firstname.error_text = "Le prénom est requis !"
            is_valid = False
        
        if not l_name:
            reg_lastname.error_text = "Le nom de famille est requis !"
            is_valid = False

        if not username:
            reg_username.error_text = "Veuillez choisir un nom d'utilisateur !"
            is_valid = False
        elif len(username) < 3:
            reg_username.error_text = "Le nom d'utilisateur doit faire au moins 3 caractères !"
            is_valid = False

        if not password:
            reg_password.error_text = "Le mot de passe ne peut pas être vide !"
            is_valid = False
        elif len(password) < 6:
            reg_password.error_text = "Le mot de passe doit faire au moins 6 caractères !"
            is_valid = False

        if not is_valid:
            page.update()
            return

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            conn.close()
            
            reg_firstname.value = ""
            reg_lastname.value = ""
            reg_username.value = ""
            reg_password.value = ""
            
            create_dlg.open = False
            join_user.value = username
            welcome_dlg.open = True
            page.update()
        except sqlite3.IntegrityError:
            reg_username.error_text = "Ce nom d'utilisateur est déjà pris !"
            page.update()

    def join_chat_click(e):
        username = join_user.value.strip()
        password = join_pass.value.strip()
        is_valid = True
        welcome_dlg.open = False
        chat_container.visible = True
        input_row.visible = True

        if not username:
            join_user.error_text = "Veuillez saisir votre identifiant !"
            is_valid = False

        if not password:
            join_pass.error_text = "Veuillez saisir votre mot de passe !"
            is_valid = False

        if not is_valid:
            page.update()
            return

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user_found = cursor.fetchone()
        conn.close()

        if user_found:
            page.session.user_name = username
            welcome_dlg.open = False
            
            new_message.prefix = ft.Text(f"{username}: ")
            chat_container.visible = True
            input_row.visible = True
            page.update()
            
            page.update()
            
            page.pubsub.send_all(Message(
                user_name=username,
                text=f"{username} a rejoint le chat.",
                message_type="login_message"
            ))
        else:
            join_user.error_text = "Identifiants ou mot de passe incorrects !"
            page.update()

    def send_message_click(e):
        user_session = getattr(page.session, "user_name", None)
        message_text = new_message.value.strip()

        if not message_text:
            new_message.error_text = "Vous ne pouvez pas envoyer un message vide !"
            page.update()
            return
            
        if user_session:
            new_message.error_text = None
            page.pubsub.send_all(Message(
                user_name=user_session,
                text=message_text,
                message_type="chat_message"
            ))
            new_message.value = ""
            page.update()

    def on_message(message: Message):
        if message.message_type == "chat_message":
            m = ChatMessage(message)
        elif message.message_type == "login_message":
            m = ft.Text(message.text, italic=True, color=ft.Colors.ON_SURFACE_VARIANT, size=12)
        chat.controls.append(m)
        page.update()

    page.pubsub.subscribe(on_message)

    reg_firstname = ft.TextField(label="Prénom", autofocus=True, on_change=update_suggested_username)
    reg_lastname = ft.TextField(label="Nom de famille", on_change=update_suggested_username)
    reg_username = ft.TextField(label="Nom d'utilisateur", on_change=clear_errors)
    reg_password = ft.TextField(label="Mot de passe (6+ car.)", password=True, can_reveal_password=True, on_change=clear_errors)

    join_user = ft.TextField(label="Nom d'utilisateur", autofocus=True, on_change=clear_errors, on_submit=join_chat_click)
    join_pass = ft.TextField(label="Mot de passe", password=True, can_reveal_password=True, on_change=clear_errors, on_submit=join_chat_click)

    welcome_dlg = ft.AlertDialog(
        open=True,
        modal=True,
        title=ft.Text("🤖 Bienvenue sur SY Chat ! 💯"),
        content=ft.Column([join_user, join_pass], width=400, height=140, tight=True, spacing=15),
        actions=[
            ft.TextButton(content=ft.Text("Créer un compte"), on_click=open_create),
            ft.Button(content=ft.Text("Se connecter"), on_click=join_chat_click)
        ],
        actions_alignment=ft.MainAxisAlignment.END
    )

    create_dlg = ft.AlertDialog(
        open=False,
        modal=True,
        title=ft.Text('😎 Créer votre compte SY ✨'),
        content=ft.Column([reg_firstname, reg_lastname, reg_username, reg_password], spacing=15, width=450, height=320, tight=True),
        actions=[
            ft.Button(content=ft.Text('Créer le compte'), on_click=join_sychat)
        ],
        actions_alignment=ft.MainAxisAlignment.END
    )

    chat = ft.ListView(expand=True, spacing=10, auto_scroll=True)
    
    new_message = ft.TextField(
        hint_text="Écrire un message...",
        border_radius=25,
        min_lines=1,
        max_lines=3,
        filled=True,
        expand=True,
        multiline=True,
        on_submit=send_message_click,
    )

    chat_container = ft.Container(
        content=chat,
        border=ft.Border.all(1, ft.Colors.OUTLINE),
        border_radius=5,
        padding=10,
        expand=True,
        visible=False,
    )

    input_row = ft.Row(
        controls=[
            new_message,
            ft.IconButton(
                icon=ft.Icons.SEND_ROUNDED,
                tooltip="Envoyer",
                on_click=send_message_click,
            ),
        ],
        visible=False,
    )
    
    page.dialog = welcome_dlg
    page.overlay.append(create_dlg)
    
    page.add(chat_container, input_row, welcome_dlg)
    
    page.update()

ft.run(main, view=ft.AppView.WEB_BROWSER, port=8080)
