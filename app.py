from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, send_from_directory, session, make_response
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
from flask_migrate import Migrate
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect, generate_csrf
import os
from pathlib import Path
from models import db, User, Post, Comment, Follow, Friendship, PrivateMessage
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from werkzeug.utils import secure_filename
from api import api
import random
import string

app = Flask(__name__)
app.config.from_object('config.Config')
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(24)  # Отдельный ключ для CSRF
app.config['WTF_CSRF_TIME_LIMIT'] = None  # Отключаем ограничение по времени для CSRF токена
app.config['WTF_CSRF_SSL_STRICT'] = False  # Отключаем строгую проверку SSL для разработки
app.config['WTF_CSRF_CHECK_DEFAULT'] = False  # Отключаем проверку CSRF для всех маршрутов по умолчанию

# Конфигурация загрузки файлов
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Создаем необходимые директории
os.makedirs(os.path.join(UPLOAD_FOLDER, 'videos'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'files'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'images'), exist_ok=True)
os.makedirs(os.path.join(app.root_path, 'static', 'avatars'), exist_ok=True)

app.config['ALLOWED_IMAGE_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['ALLOWED_VIDEO_EXTENSIONS'] = {'mp4', 'webm', 'avi', 'mov'}
app.config['ALLOWED_FILE_EXTENSIONS'] = {'pdf', 'doc', 'docx', 'txt', 'zip', 'rar'}

# Создаем папку для загрузки аватаров, если она не существует
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def get_file_type(filename):
    """Определяет тип файла на основе расширения"""
    if not '.' in filename:
        return None
    ext = filename.rsplit('.', 1)[1].lower()
    if ext in app.config['ALLOWED_IMAGE_EXTENSIONS']:
        return 'image'
    elif ext in app.config['ALLOWED_VIDEO_EXTENSIONS']:
        return 'video'
    elif ext in app.config['ALLOWED_FILE_EXTENSIONS']:
        return 'file'
    return None

def allowed_file(filename, allowed_extensions=None):
    """
    Проверяет допустимость файла.
    Если allowed_extensions не указаны, проверяет по всем разрешенным типам.
    """
    if not '.' in filename:
        return False
    
    ext = filename.rsplit('.', 1)[1].lower()
    if allowed_extensions:
        return ext in allowed_extensions
    
    return (ext in app.config['ALLOWED_IMAGE_EXTENSIONS'] or
            ext in app.config['ALLOWED_VIDEO_EXTENSIONS'] or
            ext in app.config['ALLOWED_FILE_EXTENSIONS'])

# Инициализация расширений
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.remember_cookie_duration = timedelta(days=30)
mail = Mail(app)

# Словарь для хранения кодов подтверждения и их сроков действия
verification_codes = {}

def generate_verification_code():
    """Генерирует случайный 6-значный код подтверждения"""
    return ''.join(random.choices(string.digits, k=6))

def send_verification_email(email, code):
    """Отправляет код подтверждения на указанный email"""
    msg = Message('Код подтверждения',
                 sender=app.config['MAIL_USERNAME'],
                 recipients=[email])
    msg.body = f'Ваш код подтверждения: {code}'
    mail.send(msg)

# Инициализация CSRF-защиты
csrf = CSRFProtect()
csrf.init_app(app)

# Исключаем некоторые маршруты из CSRF защиты
@csrf.exempt
def csrf_exempt_rule():
    return ['/api/posts']

# Регистрация API Blueprint
app.register_blueprint(api, url_prefix='/api')

# Создаем базу данных, если она не существует
with app.app_context():
    db.create_all()
    print("База данных инициализирована!")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    # Получаем сначала закрепленные посты
    pinned_posts = Post.query.filter_by(is_pinned=True).order_by(Post.created_at.desc()).all()
    # Затем получаем обычные посты
    regular_posts = Post.query.filter_by(is_pinned=False).order_by(Post.created_at.desc()).all()
    # Объединяем посты
    posts = pinned_posts + regular_posts
    
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует', 'error')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        
        db.session.add(user)
        db.session.commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=remember)
            response = make_response(redirect(url_for('index')))
            if remember:
                response.set_cookie('remember_token', user.get_id(), max_age=30*24*60*60)
            return response
            
        flash('Неверное имя пользователя или пароль')
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    session.clear()
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('remember_token')
    response.delete_cookie('session')
    flash('Вы успешно вышли из аккаунта', 'success')
    return response

@app.route('/api/posts', methods=['GET'])
@login_required
def posts():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return jsonify([{
        'id': post.id,
        'content': post.content,
        'image_url': post.image_url,
        'created_at': post.created_at,
        'author': post.author.username
    } for post in posts])

@app.route('/api/posts/<int:post_id>/comments', methods=['GET', 'POST'])
@login_required
def comments(post_id):
    if request.method == 'POST':
        try:
            # Проверяем CSRF токен вручную
            token = request.json.get('csrf_token') or request.headers.get('X-CSRF-Token')
            if not token or token != session.get('csrf_token'):
                return jsonify({'error': 'Invalid or missing CSRF token'}), 400
                
            if request.is_json:
                content = request.json.get('content')
            else:
                content = request.form.get('content')
                
            if not content:
                return jsonify({'error': 'Комментарий не может быть пустым'}), 400
                
            comment = Comment(
                content=content,
                user_id=current_user.id,
                post_id=post_id,
                created_at=datetime.utcnow()
            )
            
            db.session.add(comment)
            db.session.commit()
            
            # Формируем ответ с данными пользователя
            response_data = {
                "id": comment.id,
                "content": comment.content,
                "created_at": comment.created_at.strftime('%d.%m.%Y %H:%M'),
                "user": {
                    "id": current_user.id,
                    "username": current_user.username,
                    "avatar": current_user.avatar if current_user.avatar else 'default.png'
                }
            }
            
            return jsonify(response_data)
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    
    # GET запрос для получения комментариев
    comments = Comment.query.filter_by(post_id=post_id).order_by(Comment.created_at.desc()).all()
    return jsonify([{
        "id": comment.id,
        "content": comment.content,
        "created_at": comment.created_at.strftime('%d.%m.%Y %H:%M'),
        "user": {
            "id": comment.user.id,
            "username": comment.user.username,
            "avatar": comment.user.avatar if comment.user.avatar else 'default.png'
        }
    } for comment in comments])

@app.route('/api/users/<int:user_id>/follow', methods=['POST'])
@login_required
def follow_user(user_id):
    if current_user.id == user_id:
        return jsonify({'message': 'Cannot follow yourself'})
    
    follow = Follow.query.filter_by(follower_id=current_user.id, followed_id=user_id).first()
    
    if follow:
        db.session.delete(follow)
        db.session.commit()
        return jsonify({'message': 'User unfollowed'})
    
    follow = Follow(follower_id=current_user.id, followed_id=user_id)
    db.session.add(follow)
    db.session.commit()
    
    return jsonify({'message': 'User followed'})

@app.route('/friends')
@login_required
def friends():
    # Получаем список друзей и заявок в друзья
    friends = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) | (Friendship.friend_id == current_user.id)) &
        (Friendship.status == 'accepted')
    ).all()
    
    friend_requests = Friendship.query.filter(
        (Friendship.friend_id == current_user.id) &
        (Friendship.status == 'pending')
    ).all()
    
    return render_template('friends.html', friends=friends, friend_requests=friend_requests)

@app.route('/api/friends/<int:user_id>/add', methods=['POST'])
@login_required
def add_friend(user_id):
    if current_user.id == user_id:
        return jsonify({'message': 'Cannot add yourself as a friend'})
    
    # Проверяем, не существует ли уже заявка
    existing_request = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == user_id)) |
        ((Friendship.user_id == user_id) & (Friendship.friend_id == current_user.id))
    ).first()
    
    if existing_request:
        return jsonify({'message': 'Friend request already exists'})
    
    friendship = Friendship(
        user_id=current_user.id,
        friend_id=user_id,
        status='pending'
    )
    
    db.session.add(friendship)
    db.session.commit()
    
    return jsonify({'message': 'Friend request sent'})

@app.route('/api/friends/<int:request_id>/accept', methods=['POST'])
@login_required
def accept_friend(request_id):
    friendship = Friendship.query.get_or_404(request_id)
    
    if friendship.friend_id != current_user.id:
        return jsonify({'message': 'Unauthorized'})
    
    friendship.status = 'accepted'
    db.session.commit()
    
    return jsonify({'message': 'Friend request accepted'})

@app.route('/api/friends/<int:request_id>/reject', methods=['POST'])
@login_required
def reject_friend(request_id):
    friendship = Friendship.query.get_or_404(request_id)
    
    if friendship.friend_id != current_user.id:
        return jsonify({'message': 'Unauthorized'})
    
    friendship.status = 'rejected'
    db.session.commit()
    
    return jsonify({'message': 'Friend request rejected'})

@app.route('/messages')
@login_required
def messages():
    # Получаем список диалогов
    conversations = db.session.query(
        User, PrivateMessage
    ).join(
        PrivateMessage,
        (User.id == PrivateMessage.sender_id) | (User.id == PrivateMessage.receiver_id)
    ).filter(
        (PrivateMessage.sender_id == current_user.id) | (PrivateMessage.receiver_id == current_user.id)
    ).order_by(PrivateMessage.created_at.desc()).all()
    
    return render_template('messages.html', conversations=conversations)

@app.route('/messages/<int:user_id>')
@login_required
def chat(user_id):
    other_user = User.query.get_or_404(user_id)
    
    # Получаем историю сообщений
    messages = PrivateMessage.query.filter(
        ((PrivateMessage.sender_id == current_user.id) & (PrivateMessage.receiver_id == user_id)) |
        ((PrivateMessage.sender_id == user_id) & (PrivateMessage.receiver_id == current_user.id))
    ).order_by(PrivateMessage.created_at.asc()).all()
    
    # Помечаем сообщения как прочитанные
    for message in messages:
        if message.receiver_id == current_user.id and not message.is_read:
            message.is_read = True
    db.session.commit()
    
    return render_template('chat.html', other_user=other_user, messages=messages)

@app.route('/api/messages/<int:user_id>', methods=['POST'])
@login_required
def send_message(user_id):
    if request.is_json:
        content = request.json.get('content')
    else:
        content = request.form.get('content')
    
    if not content:
        return jsonify({'message': 'Message content is required'}), 400
    
    message = PrivateMessage(
        sender_id=current_user.id,
        receiver_id=user_id,
        content=content
    )
    
    db.session.add(message)
    db.session.commit()
    
    return jsonify({
        'id': message.id,
        'content': message.content,
        'created_at': message.created_at.strftime('%d.%m.%Y %H:%M'),
        'sender': {
            'id': current_user.id,
            'username': current_user.username
        }
    })

@app.route('/users')
@login_required
def users():
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('users.html', users=users)

@app.route('/users/<int:user_id>')
@login_required
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    # Получаем сначала закрепленные посты, затем обычные
    pinned_posts = Post.query.filter_by(author_id=user_id, is_pinned=True).order_by(Post.created_at.desc()).all()
    regular_posts = Post.query.filter_by(author_id=user_id, is_pinned=False).order_by(Post.created_at.desc()).all()
    posts = pinned_posts + regular_posts
    return render_template('user_profile.html', user=user, posts=posts)

@app.route('/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        flash('Файл не выбран')
        return redirect(url_for('user_profile', user_id=current_user.id))
    
    file = request.files['avatar']
    if file.filename == '':
        flash('Файл не выбран')
        return redirect(url_for('user_profile', user_id=current_user.id))
    
    if file and allowed_file(file.filename, app.config['ALLOWED_IMAGE_EXTENSIONS']):
        filename = secure_filename(f"{current_user.id}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Удаляем старый аватар, если он существует и не является дефолтным
        if current_user.avatar != 'default_avatar.png':
            old_avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.avatar)
            if os.path.exists(old_avatar_path):
                os.remove(old_avatar_path)
        
        current_user.avatar = filename
        db.session.commit()
        flash('Аватар успешно обновлен')
    else:
        flash('Недопустимый формат файла')
    
    return redirect(url_for('user_profile', user_id=current_user.id))

@app.route('/static/uploads/avatars/<filename>')
def uploaded_avatar(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/posts/<int:post_id>/pin', methods=['POST'])
@login_required
def pin_post(post_id):
    if not current_user.is_admin:
        return jsonify({'message': 'Unauthorized'}), 403
    
    post = Post.query.get_or_404(post_id)
    post.is_pinned = not post.is_pinned
    db.session.commit()
    
    return jsonify({'message': 'Post pin status updated'})

@app.route('/send_verification_code', methods=['POST'])
def send_verification():
    try:
        email = request.json.get('email')
        if not email:
            return jsonify({'error': 'Email не указан'}), 400

        # Генерируем новый код
        code = generate_verification_code()
        
        # Сохраняем код и время его истечения (15 минут)
        expiration_time = datetime.now() + timedelta(minutes=15)
        verification_codes[email] = {
            'code': code,
            'expiration_time': expiration_time
        }

        # Отправляем код на email
        send_verification_email(email, code)

        return jsonify({'message': 'Код подтверждения отправлен'}), 200

    except Exception as e:
        return jsonify({'error': 'Ошибка при отправке кода подтверждения'}), 500

@app.route('/test_email')
def test_email():
    try:
        msg = Message('Тестовое письмо',
                     sender=app.config['MAIL_DEFAULT_SENDER'],
                     recipients=['sigmastiller@gmail.com'])
        msg.body = 'Это тестовое письмо для проверки работы Flask-Mail'
        mail.send(msg)
        return 'Письмо успешно отправлено!'
    except Exception as e:
        return f'Ошибка при отправке письма: {str(e)}'

@app.route('/uploads/videos/<filename>')
def uploaded_video(filename):
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], 'videos'), filename)

@app.route('/uploads/files/<filename>')
def uploaded_file(filename):
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], 'files'), filename)

@app.context_processor
def utility_processor():
    def get_csrf_token():
        if 'csrf_token' not in session:
            session['csrf_token'] = generate_csrf()
        return session['csrf_token']
    return dict(csrf_token=get_csrf_token)

@app.after_request
def after_request(response):
    if 'csrf_token' not in session:
        session['csrf_token'] = generate_csrf()
    
    response.headers.set('X-CSRF-Token', session['csrf_token'])
    
    # Добавляем заголовки безопасности
    response.headers.set('Access-Control-Allow-Origin', '*')
    response.headers.set('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-CSRF-Token')
    response.headers.set('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    
    return response

# Обработчик OPTIONS запросов для CORS
@app.route('/', methods=['OPTIONS'])
@app.route('/<path:path>', methods=['OPTIONS'])
def options_handler(path=None):
    return '', 200

@app.route('/api/posts', methods=['POST'])
@csrf.exempt
@login_required
def create_post():
    # Проверяем CSRF токен вручную
    token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    if not token or token != session.get('csrf_token'):
        return jsonify({'error': 'Invalid or missing CSRF token'}), 400
        
    if 'content' not in request.form:
        return jsonify({'error': 'Текст поста обязателен'}), 400
    
    content = request.form['content']
    is_pinned = request.form.get('is_pinned', 'false').lower() == 'true'
    
    post = Post(
        content=content,
        author_id=current_user.id,
        is_pinned=is_pinned,
        created_at=datetime.utcnow()
    )
    
    # Обработка изображений
    if 'image' in request.files:
        image = request.files['image']
        if image and image.filename and allowed_file(image.filename, app.config['ALLOWED_IMAGE_EXTENSIONS']):
            try:
                filename = secure_filename(f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{image.filename}")
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'images', filename)
                os.makedirs(os.path.dirname(image_path), exist_ok=True)
                image.save(image_path)
                post.image_url = f"images/{filename}"
            except Exception as e:
                return jsonify({'error': f'Ошибка при загрузке изображения: {str(e)}'}), 500
        elif image and image.filename:
            return jsonify({'error': 'Недопустимый формат изображения'}), 400
    
    # Обработка видео
    if 'video' in request.files:
        video = request.files['video']
        if video and video.filename and allowed_file(video.filename, app.config['ALLOWED_VIDEO_EXTENSIONS']):
            try:
                filename = secure_filename(f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{video.filename}")
                video_path = os.path.join(app.config['UPLOAD_FOLDER'], 'videos', filename)
                os.makedirs(os.path.dirname(video_path), exist_ok=True)
                video.save(video_path)
                post.video_url = f"videos/{filename}"
            except Exception as e:
                return jsonify({'error': f'Ошибка при загрузке видео: {str(e)}'}), 500
        elif video and video.filename:
            return jsonify({'error': 'Недопустимый формат видео'}), 400
    
    # Обработка файлов
    if 'file' in request.files:
        file = request.files['file']
        if file and file.filename and allowed_file(file.filename, app.config['ALLOWED_FILE_EXTENSIONS']):
            try:
                filename = secure_filename(f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'files', filename)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                file.save(file_path)
                post.file_url = f"files/{filename}"
                post.file_name = file.filename
                post.file_type = file.filename.rsplit('.', 1)[1].lower()
            except Exception as e:
                return jsonify({'error': f'Ошибка при загрузке файла: {str(e)}'}), 500
        elif file and file.filename:
            return jsonify({'error': 'Недопустимый формат файла'}), 400
    
    try:
        db.session.add(post)
        db.session.commit()
        
        return jsonify({
            'message': 'Пост успешно создан',
            'post': {
                'id': post.id,
                'content': post.content,
                'image_url': post.image_url if hasattr(post, 'image_url') else None,
                'video_url': post.video_url if hasattr(post, 'video_url') else None,
                'file_url': post.file_url if hasattr(post, 'file_url') else None,
                'file_name': post.file_name if hasattr(post, 'file_name') else None,
                'created_at': post.created_at.isoformat(),
                'author': {
                    'id': current_user.id,
                    'username': current_user.username,
                    'avatar': current_user.avatar
                }
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Ошибка при сохранении поста: {str(e)}'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 