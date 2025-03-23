from datetime import time, timedelta
import random
from flask_jwt_extended import create_access_token, create_refresh_token, decode_token, get_jwt_identity, jwt_required
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from numpy import identity
from sqlalchemy import desc, func
from appstarcatcher import db , app ,limiter,csrf
from flask import jsonify, render_template, request, redirect, session, url_for, flash
from werkzeug.utils import secure_filename
import os
from flask_wtf.csrf import generate_csrf
from werkzeug.security import generate_password_hash ,check_password_hash
from flask_wtf.csrf import CSRFProtect
from functools import wraps
from werkzeug.exceptions import NotFound
from rembg import remove  # ✅ مكتبة إزالة الخلفية
import time
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from appstarcatcher.forms import AdminMarketListingForm, ClubForm, LoginForm, PackForm, PlayerForm, RegistrationForm, SubscriptionForm
from appstarcatcher.models import AdminMarketListing, ClubDetail, GeneratedPlayer, Pack, PackPurchase, Player, Subscription, User, UserClub, UserPlayer, UserSubscriptionPurchase, generate_random_code

# دالة التحقق من كلمة المرور
def verify_password(password_hash, password):
    return check_password_hash(password_hash, password)

# إعدادات رفع الصور
UPLOAD_FOLDER = 'appstarcatcher/static/uploads/image_player'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER_IMAGE_PLAYER'] = UPLOAD_FOLDER
login_manager = LoginManager(app)


#======================packs

# إعداد المجلد لتحميل الصور
app.config['UPLOAD_FOLDER_PACKS'] = 'appstarcatcher/static/uploads/packs'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # الحد الأقصى لحجم الملف 5MB

app.config['UPLOAD_FOLDER_CLUB'] = 'appstarcatcher/static/uploads/clubs'
app.config['UPLOAD_FOLDER_BANNERCLUBS'] = 'appstarcatcher/static/uploads/clubs/bannerclub'

#=======================================================================================================================
#=======================================================================================================================
#=======================================================================================================================
#=======================================================================================================================
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('غير مصرح لك بالوصول إلى هذه الصفحة', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    # التحقق من تسجيل الدخول مسبقاً
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('dashboard'))
        return redirect(url_for('home'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        # تنظيف البيانات المدخلة
        email = form.email.data.lower().strip()
        password_hash = form.password.data
        
        try:
            user = User.query.filter_by(email=email).first()
            
            if user and user.check_password(password_hash):
                # تحديث معلومات تسجيل الدخول
                user.last_login = datetime.utcnow()
                user.login_attempts = 0  # إعادة تعيين عدد المحاولات
                db.session.commit()
                
                # تسجيل الدخول
                login_user(user, remember=form.remember.data, duration=timedelta(days=30))
                
                # تخزين معلومات الجلسة
                session['user_id'] = user.id
                session['is_admin'] = user.is_admin
                session['login_time'] = datetime.utcnow().timestamp()
                session.permanent = True
                
                # التوجيه حسب نوع المستخدم
                if user.is_admin:
                    flash('تم تسجيل الدخول بنجاح!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('تم تسجيل الدخول بنجاح!', 'success')
                    return redirect(url_for('home'))
            else:
                # زيادة عدد محاولات تسجيل الدخول الفاشلة
                if user:
                    user.login_attempts = (user.login_attempts or 0) + 1
                    if user.login_attempts >= 5:  # قفل الحساب بعد 5 محاولات فاشلة
                        user.is_locked = True
                        user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                    db.session.commit()
                
                time.sleep(1)  # تأخير لمنع محاولات التخمين
                flash('البريد الإلكتروني أو كلمة المرور غير صحيحة', 'error')
        
        except Exception as e:
            db.session.rollback()
            flash('حدث خطأ أثناء تسجيل الدخول. يرجى المحاولة مرة أخرى', 'error')
    
    return render_template('login.html', form=form)



@app.route('/logout')
@login_required
def logout():
    # حذف جميع بيانات الجلسة
    session.clear()
    logout_user()
    flash('تم تسجيل الخروج بنجاح', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
@admin_required
def dashboard():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    login_time = session.get('login_time')
    session_timeout = app.config['PERMANENT_SESSION_LIFETIME'].total_seconds()
    
    if login_time and (datetime.utcnow().timestamp() - login_time > session_timeout):
        session.clear()
        logout_user()
        flash('انتهت صلاحية الجلسة. يرجى تسجيل الدخول مرة أخرى', 'warning')
        return redirect(url_for('login'))
    
    try:
        form = PackForm()
        formmarket = AdminMarketListingForm()
        packs = Pack.query.filter_by(is_active=True).all()
        listings = AdminMarketListing.query\
            .filter(AdminMarketListing.expires_at > datetime.utcnow())\
            .join(Player)\
            .all()

        listings_data = []
        for listing in listings:
            listings_data.append({
                'id': listing.id,
                'player_id': listing.player_id,
                'player_name': listing.player.name,
                'player_rating': listing.player.rating,
                'rarity': listing.player.rarity,
                'player_position': listing.player.position,
                'price': listing.price,
                'player_image_url' : listing.player.image_url,
                'expires_at': listing.expires_at.isoformat(),
                'status': listing.status
            })
        csrf_token_value=generate_csrf()
        count_player=Player.query.count()
        return render_template('dashboard.html',
                            form=form,
                            formmarket=formmarket,
                            packs=packs,
                            username=current_user.username,
                            csrf_token=csrf_token_value,
                            listings=listings_data,
                            count_player=count_player)
    except Exception as e:
        app.logger.error(f"Error in dashboard route: {str(e)}")
        flash('حدث خطأ أثناء تحميل الصفحة', 'error')
        return redirect(url_for('error_page'))

# التعامل مع محاولات الوصول غير المصرح به
@app.errorhandler(401)
def unauthorized(error):
    flash('يجب تسجيل الدخول للوصول إلى هذه الصفحة', 'error')
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden(error):
    flash('غير مصرح لك بالوصول إلى هذه الصفحة', 'error')
    return redirect(url_for('index'))




# إنشاء باكج جديد
@app.route('/packs', methods=['POST'])
def create_pack():
    if request.method == 'POST':
        try:
            # التحقق من البيانات المستلمة
            form_data = request.form
            file = request.files.get('image')
            
            # معالجة الصورة إذا تم تحميلها
            image_url = None
            if file and file.filename:
                filename = secure_filename(file.filename)  # تأكيد الاسم الآمن
                filepath = os.path.join(app.config['UPLOAD_FOLDER_PACKS'], filename)  # تحديد المسار الكامل
                file.save(filepath)  # حفظ الصورة في المجلد
                image_url = f'/static/uploads/packs/{filename}'  # المسار الذي سيتم عرضه للمستخدم   
            
            # تجميع نسب النادرية
            rarity_odds = {
                'common': int(form_data.get('rarity_common', 70)),
                'rare': int(form_data.get('rarity_rare', 20)),
                'epic': int(form_data.get('rarity_epic', 8)),
                'legendary': int(form_data.get('rarity_legendary', 2))
            }
            
            # إنشاء باكج جديد
            new_pack = Pack(
                name=form_data['name'],
                description=form_data['description'],
                price=int(form_data['price']),
                player_count=int(form_data['player_count']),
                image_url=image_url,
                rarity_odds=rarity_odds,
                is_active=bool(form_data.get('is_active', True))
            )
            
            # حفظ الباكج في قاعدة البيانات
            db.session.add(new_pack)
            db.session.commit()
            
            # إرجاع استجابة JSON
            return jsonify({
                'status': 'success',
                'message': 'تم إضافة الباكج بنجاح',
                'pack': {
                    'id': new_pack.id,
                    'name': new_pack.name,
                    'price': new_pack.price,
                    'image_url': new_pack.image_url
                }
            }), 201
            
        except Exception as e:
            # إرجاع استجابة خطأ في حالة حدوث مشكلة
            db.session.rollback()
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 400
        


#==================================  حذف الباكج

# حذف باكج
@app.route('/packs/<int:pack_id>', methods=['DELETE'])
@csrf.exempt
def delete_pack(pack_id):
    try:
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({
                'status': 'error',
                'message': 'غير مصرح لك بحذف الباكجات'
            }), 403

        # First delete related pack_purchases
        pack = Pack.query.get_or_404(pack_id)

        # Delete related PackPurchase records first
        PackPurchase.query.filter_by(pack_id=pack_id).delete()

        # Delete the pack's image if it exists
        if pack.image_url:
            try:
                image_path = os.path.join(app.config['UPLOAD_FOLDER_PACKS'], os.path.basename(pack.image_url))
                if os.path.exists(image_path):
                    os.remove(image_path)
            except Exception as e:
                app.logger.error(f"Error deleting pack image: {str(e)}")

        # Now delete the pack
        db.session.delete(pack)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'تم حذف الباكج وكل البيانات المرتبطة به بنجاح'
        }), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting pack: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'حدث خطأ أثناء حذف الباكج: {str(e)}'
        }), 500



@app.route('/catalog')
@login_required
def catalog():
    # تعديل الاستعلام لإرجاع كائنات ClubDetail بدلاً من Row objects
    clubs = db.session.query(ClubDetail).all()
    
    # تجهيز بيانات الأندية بشكل صحيح
    clubs_data = []
    for club in clubs:
        clubs_data.append({
            'club_id': club.club_id,
            'club_name': club.club_name,
            'club_color': club.club_color,
            'club_image_url': url_for('static', filename=f'uploads/clubs/{club.club_image_url}') if club.club_image_url else None
        })
    
    return render_template('catalog/index.html', clubs=clubs_data)



@app.route('/catalog/<int:club_id>')
@login_required 
def club_catalog(club_id):
    try:
        club = ClubDetail.query.get_or_404(club_id)
        
        # جلب جميع اللاعبين في النادي وترتيبهم حسب المركز والتقييم
        club_players = Player.query.filter_by(club_id=club_id).order_by(
            Player.position, Player.rating.desc()
        ).all()
        
        # جلب اللاعبين الذين قام المستخدم بجمعهم
        collected_players = db.session.query(UserClub).filter(
            UserClub.user_id == current_user.id,
            UserClub.club_id == club_id
        ).all()
        
        # إنشاء مجموعة تحتوي على معرفات اللاعبين المجمعين
        collected_ids = {cp.player_id for cp in collected_players}
        
        # تنظيم جميع اللاعبين داخل كل مركز
        squad = {}
        positions = set(p.position for p in club_players)  # استخراج جميع المراكز
        
        for position in positions:
            position_players = [p for p in club_players if p.position == position]
            
            # تخزين جميع اللاعبين في هذا المركز
            squad[position] = [
                {
                    'id': p.id,
                    'name': p.name,
                    'position': position,
                    'rating': p.rating,
                    'image_url': p.image_url if p.id in collected_ids else None,
                    'rarity': p.rarity,
                    'is_collected': p.id in collected_ids
                }
                for p in position_players
            ]

        # حساب نسبة الإنجاز في جمع اللاعبين
        total_players = len(club_players)
        collected_count = len(collected_ids)
        completion_percentage = (collected_count / total_players * 100) if total_players > 0 else 0

        return render_template('catalog/club.html',
                          club=club,
                          squad=squad,
                          total_players=total_players,
                          collected_count=collected_count,
                          completion_percentage=completion_percentage)

    except Exception as e:
        app.logger.error(f"Error in club_catalog: {str(e)}")
        flash('حدث خطأ أثناء تحميل الكتالوج', 'error')
        return redirect(url_for('catalog'))


@app.route('/get_club_players/<int:club_id>')
@login_required
def get_club_players(club_id):
    players = Player.query.filter_by(club_id=club_id).all()
    collected = UserClub.query.filter_by(
        user_id=current_user.id,
        club_id=club_id
    ).with_entities(UserClub.player_id).all()
    collected_ids = [c.player_id for c in collected]
    
    return jsonify({
        'players': [{
            'id': p.id,
            'name': p.name,
            'position': p.position,
            'image_url': p.image_url if p.id in collected_ids else None,
            'is_collected': p.id in collected_ids
        } for p in players]
    })


#اضافة لاعب للسوق

@app.route('/add_listing', methods=['POST'])
@login_required
def add_listing():
    if not current_user.is_admin:
        app.logger.warning(f'Non-admin user {current_user.id} attempted to add listing')
        return jsonify({
            'status': 'error',
            'message': 'غير مصرح لك بإضافة لاعبين للسوق'
        }), 403

    try:
        if not request.is_json:
            return jsonify({
                'status': 'error',
                'message': 'نوع الطلب غير صحيح'
            }), 400

        data = request.get_json()
        
        # التحقق من وجود الحقول المطلوبة
        required_fields = ['player_id', 'price', 'expires_at', 'status']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'status': 'error',
                    'message': f'الحقل {field} مطلوب'
                }), 400

        # التحقق من وجود اللاعب
        player = Player.query.get(data.get('player_id'))
        if not player:
            return jsonify({
                'status': 'error',
                'message': 'اللاعب غير موجود'
            }), 404

        # التحقق من أن اللاعب ليس مدرجًا بالفعل في السوق
        existing_listing = AdminMarketListing.query.filter(
            AdminMarketListing.player_id == player.id,
            AdminMarketListing.expires_at > datetime.utcnow()  # التأكد من أن العرض لم ينتهِ بعد
        ).first()

        if existing_listing:
            return jsonify({
                'status': 'error',
                'message': 'اللاعب مدرج بالفعل في السوق'
            }), 400

        try:
            expires_at = datetime.strptime(data['expires_at'], '%Y-%m-%dT%H:%M')
        except ValueError:
            return jsonify({
                'status': 'error',
                'message': 'صيغة التاريخ غير صحيحة'
            }), 400

        if expires_at <= datetime.utcnow():
            return jsonify({
                'status': 'error',
                'message': 'تاريخ الانتهاء يجب أن يكون في المستقبل'
            }), 400

        # إنشاء القائمة الجديدة
        new_listing = AdminMarketListing(
            player_id=player.id,
            price=int(data['price']),
            expires_at=expires_at,
            status=data['status'],
            listed_at=datetime.utcnow(),
            admin_id=current_user.id
        )

        db.session.add(new_listing)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'تم إضافة اللاعب إلى السوق بنجاح',
            'listing': {
                'id': new_listing.id,
                'player_id': new_listing.player_id,
                'price': new_listing.price,
                'expires_at': new_listing.expires_at.isoformat(),
                'status': new_listing.status
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in add_listing: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'حدث خطأ أثناء إضافة اللاعب للسوق'
        }), 500



@app.route('/get_players')
@login_required
def get_players():
    try:
        # جلب جميع اللاعبين بدون فلتر is_active
        players = Player.query.all()
        
        if not players:
            app.logger.warning('لا يوجد لاعبين')
            return jsonify({
                'status': 'success',
                'players': []
            })

        return jsonify({
            'status': 'success',
            'players': [{
                'id': p.id,
                'name': p.name,
                'rating': p.rating,
                'position': p.position
            } for p in players]
        })

    except Exception as e:
        app.logger.error(f'Error in get_players: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'حدث خطأ أثناء جلب قائمة اللاعبين'
        }), 500   
    

@app.route('/delete-player-market/<int:id>', methods=['DELETE'])
def delete_player_market(id):
    # تأكد من طباعة المعرّف للتحقق
    print(f"Attempting to delete player with ID: {id}")
    
    try:
        player = AdminMarketListing.query.get(id)
        
        if player is None:
            return jsonify({"message": "اللاعب غير موجود"}), 404
            
        db.session.delete(player)
        db.session.commit()
            
        return jsonify({"message": "تم الحذف بنجاح"}), 200
    
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting player: {str(e)}")
        return jsonify({
            "message": "حدث خطأ أثناء الحذف",
            "error": str(e)
        }), 500

@app.route('/add_player', methods=['GET', 'POST'])
@login_required
@admin_required
def add_player():
    form = PlayerForm()
    clubs = ClubDetail.query.order_by(ClubDetail.club_name).all()
    form.club.choices = [(club.club_id, club.club_name) for club in clubs]  # استخدام club_id

    if form.validate_on_submit():
        # معالجة الصورة وإزالة الخلفية
        if form.image_url.data:
            filename = secure_filename(form.image_url.data.filename)
            original_ext = os.path.splitext(filename)[1].lower()  # استخراج الامتداد الأصلي
            original_path = os.path.join(app.config['UPLOAD_FOLDER_IMAGE_PLAYER'], filename)

            # حفظ الصورة مؤقتًا
            form.image_url.data.save(original_path)

            # فتح الصورة ومعالجتها
            with open(original_path, "rb") as file:
                input_image = file.read()
            
            output_image = remove(input_image)  # ✅ إزالة الخلفية

            # إنشاء كود فريد مكون من 6 أحرف وأرقام
            def generate_unique_code(length=6):
                import random
                import string
                characters = string.ascii_uppercase + string.ascii_lowercase + string.digits
                while True:
                    # إنشاء كود عشوائي
                    code = ''.join(random.choice(characters) for _ in range(length))
                    
                    # التحقق من أن الكود غير موجود في أسماء الصور الحالية
                    existing_images = [f for f in os.listdir(app.config['UPLOAD_FOLDER_IMAGE_PLAYER']) 
                                       if os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER_IMAGE_PLAYER'], f))]
                    
                    if not any(code in img_name for img_name in existing_images):
                        return code

            unique_code = generate_unique_code()
            
            # تحديد اسم جديد للصورة بعد إزالة الخلفية مع إضافة الكود الفريد
            base_name = os.path.splitext(filename)[0]
            new_filename = f"{base_name}_{unique_code}_no_bg.png"
            final_path = os.path.join(app.config['UPLOAD_FOLDER_IMAGE_PLAYER'], new_filename)

            # ✅ التحقق من أن الصورة تمت معالجتها بنجاح قبل حذف الأصلية
            with open(final_path, "wb") as file:
                file.write(output_image)

            # ✅ إذا لم تكن الصورة الأصلية بصيغة PNG، يمكن حذفها
            os.remove(original_path)

            image_path = new_filename  # ✅ تخزين اسم الصورة بعد إزالة الخلفية
        else:
            image_path = None

        # البحث عن النادي باستخدام club_id
        club = ClubDetail.query.get(form.club.data)

        # إنشاء لاعب جديد
        player = Player(
            name=form.name.data,
            rating=form.rating.data,
            position=form.position.data,
            image_url=image_path,
            rarity=form.rarity.data,
            nationality=form.nationality.data,
            club_id=club.club_id  # تعيين club_id بدلاً من club
        )

        db.session.add(player)
        db.session.commit()

        flash('تم إضافة اللاعب بنجاح بعد إزالة الخلفية!', 'success')
        return redirect(url_for('add_player'))

    players = Player.query.order_by(Player.rating.desc()).all()
    username = current_user.username

    return render_template('add_player.html', form=form,
                           players=players,
                           username=username)

@app.route('/delete_player/', methods=['DELETE'])
def delete_player():
    try:
        data = request.get_json()
        if not data or 'player_id' not in data:
            return jsonify({'error': 'معرّف اللاعب مطلوب'}), 400
        
        player_id = data['player_id']
        player = Player.query.get_or_404(player_id)
        db.session.delete(player)
        db.session.commit()
        return jsonify({'message': 'تم حذف اللاعب بنجاح'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'حدث خطأ أثناء حذف اللاعب'}), 500



@app.route('/error')
def error_page():
    error_msg = session.get('error_message', 'حدث خطأ غير متوقع')
    error_code = session.get('error_code', 500)
    return render_template('error.html', 
                         error_message=error_msg, 
                         error_code=error_code)




# Route for adding a new club
@app.route('/add_club', methods=['GET', 'POST'])
@login_required
@admin_required
def add_club():
    form = ClubForm()
    
    if form.validate_on_submit():
        club_image_url = None
        if form.club_image.data:
            # Handle image upload here
            filename = secure_filename(form.club_image.data.filename)
            form.club_image.data.save(os.path.join(app.config['UPLOAD_FOLDER_CLUB'], filename))
            club_image_url = filename


        if form.banner_image.data:
            banner_image = form.banner_image.data
            banner_image_filename = secure_filename(banner_image.filename)
            banner_image_path = os.path.join(app.config['UPLOAD_FOLDER_BANNERCLUBS'], banner_image_filename)
            banner_image.save(banner_image_path)

# الحصول على قيمة اللون
        club_color = form.club_color.data

        new_club = ClubDetail(
            club_name=form.club_name.data,
            founded_year=form.founded_year.data,
            coach_name=form.coach_name.data,
            club_image_url=club_image_url,
            banner_image_url=banner_image_filename,  # رابط صورة البنر
            num_players=form.num_players.data,
            club_color=club_color,  # اللون
        )
        
        db.session.add(new_club)
        db.session.commit()
        
        flash('تم إضافة النادي بنجاح!', 'success')
        return redirect(url_for('add_club'))

    clubs = ClubDetail.query.all()
    username =current_user.username

    return render_template('add_club.html', form=form, clubs=clubs,
                           username=username)


@app.route('/delete_club/<int:club_id>', methods=['DELETE'])
def delete_club(club_id):
    try:
        # طباعة رسالة تشخيص
        print(f"Attempting to delete club with ID: {club_id}")
        
        # البحث عن النادي
        club = ClubDetail.query.get(club_id)
        
        if club is None:
            print(f"Club with ID {club_id} not found")
            return jsonify({"message": "النادي غير موجود"}), 404
            
        # حذف النادي
        db.session.delete(club)
        db.session.commit()
        
        print(f"Successfully deleted club with ID: {club_id}")
        return jsonify({"message": "تم الحذف بنجاح"}), 200
        
    except Exception as e:
        # طباعة تفاصيل الخطأ
        print(f"Error deleting club: {str(e)}")
        db.session.rollback()
        return jsonify({
            "message": "حدث خطأ أثناء الحذف",
            "error": str(e)
        }), 500

        
@app.route('/edit_club/<int:club_id>', methods=['POST'])
@csrf.exempt
def edit_club(club_id):
    try:
        club = ClubDetail.query.get_or_404(club_id)
        
        # تحديث بيانات النادي - استخدام الأسماء الصحيحة من النموذج
        club.club_name = request.form['edit_club_name']
        club.coach_name = request.form['edit_coach_name']
        club.founded_year = request.form['edit_founded_year']
        club.num_players = request.form['edit_num_players']
        club.club_color = request.form['edit_club_color']
        
        # معالجة تحميل الصور - استخدام الأسماء الصحيحة من النموذج
        if 'edit_club_image' in request.files:
            club_image = request.files['edit_club_image']
            if club_image and club_image.filename:
                filename = secure_filename(club_image.filename)
                club_image.save(os.path.join(app.config['UPLOAD_FOLDER_CLUB'], filename))
                club.club_image_url = filename
        
        if 'edit_banner_image' in request.files:
            banner_image = request.files['edit_banner_image']
            if banner_image and banner_image.filename:
                banner_filename = secure_filename(banner_image.filename)
                banner_image.save(os.path.join(app.config['UPLOAD_FOLDER_BANNERCLUBS'], banner_filename))
                club.banner_image_url = banner_filename
        
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'تم تحديث بيانات النادي بنجاح'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'error': 'حدث خطأ أثناء تحديث بيانات النادي'
        }), 500

@app.route('/get_club/<int:club_id>')
def get_club(club_id):
    try:
        club = ClubDetail.query.get_or_404(club_id)
        return jsonify({
            'club_name': club.club_name,
            'coach_name': club.coach_name,
            'founded_year': club.founded_year,
            'num_players': club.num_players,
            'club_color': club.club_color,
            'club_image_url': club.club_image_url or '',
            'banner_image_url': club.banner_image_url or ''
        })
    except Exception as e:
        return jsonify({'error': 'النادي غير موجود'}), 404


@app.route('/add_subscription', methods=['GET', 'POST'])
@login_required
@admin_required
def add_subscription():
    form = SubscriptionForm()

    if form.validate_on_submit():
        # إضافة اشتراك جديد
        subscription = Subscription(
            package_type=form.package_type.data,
            package_details=form.package_details.data,
            price=form.price.data,
            is_outside_egypt=form.is_outside_egypt.data
        )

        # إضافة الاشتراك إلى قاعدة البيانات
        db.session.add(subscription)
        db.session.commit()

        flash('تم إضافة الاشتراك بنجاح!', 'success')
        return redirect(url_for('add_subscription'))  # إعادة التوجيه إلى نفس الصفحة لإضافة اشتراكات أخرى

    subscriptions = Subscription.query.all()  # استرجاع جميع الاشتراكات لعرضها إذا لزم الأمر

    return render_template('add_subscription.html', form=form, 
                           subscriptions=subscriptions,
                           username=current_user.username)


@app.route('/delete_subscription/<int:id>', methods=['DELETE'])
def delete_subscription(id):
    try:
        # طباعة رسالة تشخيص
        print(f"Attempting to delete club with ID: {id}")
        
        subscription = Subscription.query.get(id)
        
        if subscription is None:
            print(f"Club with ID {id} not found")
            return jsonify({"message": "النادي غير موجود"}), 404
            
        db.session.delete(subscription)
        db.session.commit()
        
        print(f"Successfully deleted club with ID: {id}")
        return jsonify({"message": "تم الحذف بنجاح"}), 200
        
    except Exception as e:
        # طباعة تفاصيل الخطأ
        print(f"Error deleting club: {str(e)}")
        db.session.rollback()
        return jsonify({
            "message": "حدث خطأ أثناء الحذف",
            "error": str(e)
        }), 500



@app.route('/buy_market_player', methods=['POST'])
@login_required
def buy_market_player():
    try:
        data = request.get_json()
        listing_id = data.get('listing_id')

        if not listing_id:
            return jsonify({
                'status': 'error',
                'message': 'معرف القائمة مطلوب'
            }), 400

        # التحقق من وجود القائمة
        listing = AdminMarketListing.query.get(listing_id)
        if not listing or listing.status != 'active':
            return jsonify({
                'status': 'error',
                'message': 'هذا العرض غير متوفر'
            }), 404

        # التحقق من تاريخ انتهاء العرض
        if listing.expires_at and listing.expires_at < datetime.utcnow():
            return jsonify({
                'status': 'error',
                'message': 'هذا العرض منتهي'
            }), 400

        # التحقق من امتلاك العملات الكافية
        if current_user.coins < listing.price:
            return jsonify({
                'status': 'error',
                'message': 'لا تملك عملات كافية لشراء هذا اللاعب'
            }), 400

        # الحصول على معلومات اللاعب
        player = Player.query.get(listing.player_id)
        if not player:
            return jsonify({
                'status': 'error',
                'message': 'اللاعب غير موجود'
            }), 404

        # إنشاء سجل جديد في UserPlayer
        user_player = UserPlayer(
            user_id=current_user.id,
            player_id=player.id,
            position=player.position,
            is_listed=False,
            price=listing.price,
            acquired_at=datetime.utcnow(),
            sale_code=generate_random_code()
        )

        # خصم العملات من المستخدم
        current_user.coins -= listing.price

        # تحديث حالة القائمة

        # حفظ التغييرات
        db.session.add(user_player)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'تم شراء اللاعب بنجاح',
            'data': {
                'player_name': player.name,
                'price_paid': listing.price,
                'remaining_coins': current_user.coins,
                'sale_code': user_player.sale_code
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in buy_market_player: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'حدث خطأ أثناء شراء اللاعب: {str(e)}'
        }), 500



#=============================  API  ====================================
#=============================  API  ====================================
#=============================  API  ====================================


# رووت API للتسجيل
# دالة تهييش كلمة المرور
def hash_password(password):
    # استخدام خوارزمية pbkdf2:sha256 مع 600000 تكرار وملح عشوائي
    return generate_password_hash(password, method='pbkdf2:sha256:600000', salt_length=16)

# رووت API للتسجيل
@app.route('/register', methods=['GET', 'POST'])
def register():
    # If user is already logged in, redirect
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    # Handle API request (JSON)
    if request.is_json:
        try:
            data = request.get_json()
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')

            if not username or not email or not password:
                return jsonify({'success': False, 'message': 'Missing required fields'}), 400

            if User.query.filter_by(username=username).first():
                return jsonify({'success': False, 'message': 'Username already exists'}), 400

            if User.query.filter_by(email=email).first():
                return jsonify({'success': False, 'message': 'Email already registered'}), 400

            password_hash = hash_password(password)
            user = User(username=username, email=email, password_hash=password_hash)
            db.session.add(user)
            db.session.commit()

            access_token = create_access_token(identity=str(user.id))
            refresh_token = create_refresh_token(identity=str(user.id))

            return jsonify({
                "success": True,
                "message": "User registered successfully",
                "data": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "coins": user.coins,
                    "token": access_token,
                    "refresh_token": refresh_token
                }
            }), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)}), 500

    # Handle web form request
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            # Process profile image if uploaded
            image_url = None
            if form.profile_image.data:
                filename = secure_filename(form.profile_image.data.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                form.profile_image.data.save(filepath)
                image_url = filename

            # Create new user
            user = User(
                username=form.username.data,
                email=form.email.data.lower(),
                phone=form.phone.data,
                country=form.country.data,
                state=form.state.data,
                city=form.city.data,
                image_url=image_url
            )
            user.set_password(form.password.data)
            
            db.session.add(user)
            db.session.commit()

            flash('تم إنشاء حسابك بنجاح! يمكنك تسجيل الدخول الآن.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            flash('حدث خطأ أثناء إنشاء الحساب. الرجاء المحاولة مرة أخرى.', 'danger')
            app.logger.error(f"Registration error: {str(e)}")
    
    return render_template('register.html', form=form)

# رووت API لتسجيل الدخول
@app.route('/api_login', methods=['POST'])
@csrf.exempt
def login_api():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if user and verify_password(user.password_hash, password):  # التحقق من تطابق كلمة المرور
        # When creating tokens, ensure user_id is converted to string
        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity.str(user.id))
        
        return jsonify({
            "success": True,
            "message": "تم تسجيل الدخول بنجاح!",
            "data": {
                "id": user.id,
                "username": user.username,
                "name": user.username,  # استخدام username كاسم للمستخدم
                "email": email,
                "coins": user.coins,
                "token": access_token,
                "refresh_token": refresh_token
            }
        }), 200
    else:
        return jsonify({
            "success": False,
            "message": "البريد الإلكتروني or كلمة المرور غير صحيحة"
        }), 401

# رووت للتحقق من صلاحية التوكن
@app.route('/validate_token', methods=['GET'])
@jwt_required()
def validate_token():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if user:
        return jsonify({
            "success": True,
            "message": "التوكن صالح",
            "user_id": current_user_id
        }), 200
    else:
        return jsonify({
            "success": False,
            "message": "التوكن غير صالح or المستخدم غير موجود"
        }), 401

# رووت لتحديث التوكن
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user_id = get_jwt_identity()
    access_token = create_access_token(identity=current_user_id)
    
    return jsonify({
        "success": True,
        "access_token": access_token
    }), 200




#=============================  API packs ====================================
#=============================  API packs ====================================

@app.route('/api_packs', methods=['GET'])
def api_packs():
    try:
        # استرجاع جميع الباكجات من قاعدة البيانات
        packs = Pack.query.all()

        # تحويل الباكجات إلى قائمة من القواميس (dictionaries)
        pack_list = []
        for pack in packs:
            pack_list.append({
                'id': pack.id,
                'name': pack.name,
                'description': pack.description,
                'image_url': pack.image_url,
                'price': pack.price,
                'player_count': pack.player_count,
                'rarity_odds': pack.rarity_odds,
                'is_active': pack.is_active,
                'created_at': pack.created_at
            })

        # إرجاع الباكجات على شكل JSON
        return jsonify({
            'status': 'success',
            'packs': pack_list
        }), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500



@app.route('/open_pack/<int:pack_id>', methods=['POST', 'OPTIONS'])
@csrf.exempt
def open_pack(pack_id):
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        # التحقق من التوكن والمستخدم
        auth_header = request.headers.get('Authorization')
        if (auth_header and auth_header.startswith('Bearer ')):
            token = auth_header.split(' ')[1]
            
            try:
                user_claims = decode_token(token)
                user_id = user_claims['sub']
                current_user = User.query.get(user_id)
                
                if not current_user:
                    return jsonify({'status': 'error', 'message': 'مستخدم غير موجود'}), 401
                
                login_user(current_user)
            except Exception:
                return jsonify({'status': 'error', 'message': 'رمز المصادقة غير صالح'}), 401
        else:
            return jsonify({'status': 'error', 'message': 'يجب تسجيل الدخول للوصول إلى هذه الصفحة'}), 401

        # التحقق من الباكج
        pack = Pack.query.get_or_404(pack_id)
        
        if not pack.is_active:
            return jsonify({'status': 'error', 'message': 'هذا الباكج غير متاح حالياً'}), 400
        
        if current_user.coins < pack.price:
            return jsonify({'status': 'error', 'message': 'ليس لديك عملات كافية لفتح هذا الباكج'}), 400
        
        # جلب جميع اللاعبين المتاحين
        all_players = Player.query.all()
        
        if not all_players:
            return jsonify({'status': 'error', 'message': 'لا يوجد لاعبين في النظام. يرجى المحاولة لاحقاً.'}), 404
        
        # خصم العملات
        current_user.coins -= pack.price
        
        # تصنيف اللاعبين حسب الندرة
        players_by_rarity = {
            'common': [p for p in all_players if p.rarity == 'common'],
            'rare': [p for p in all_players if p.rarity == 'rare'],
            'epic': [p for p in all_players if p.rarity == 'epic'],
            'legendary': [p for p in all_players if p.rarity == 'legendary']
        }
        
        # التحقق من توفر اللاعبين لكل ندرة
        missing_rarities = []
        for rarity, count in pack.rarity_odds.items():
            if count > 0 and not players_by_rarity.get(rarity, []):
                missing_rarities.append(rarity)
        
        if missing_rarities:
            db.session.rollback()  # إلغاء خصم العملات
            return jsonify({'status': 'error', 'message': f'لا يوجد لاعبين من الفئات التالية: {", ".join(missing_rarities)}. يرجى المحاولة لاحقاً.'}), 404
        
        # قائمة لتتبع اللاعبين المضافين ومنع التكرار
        selected_players = set()
        players_received = []

        while len(players_received) < pack.player_count:
            available_rarities = [r for r in pack.rarity_odds.keys() if pack.rarity_odds[r] > 0 and players_by_rarity.get(r, [])]
            
            if not available_rarities:
                break  # لا يوجد المزيد من اللاعبين
            
            # اختيار ندرة عشوائية
            weights = [pack.rarity_odds[r] for r in available_rarities]
            rarity = random.choices(population=available_rarities, weights=weights, k=1)[0]

            # اختيار لاعب عشوائي من الندرة المحددة مع شرط عدم التكرار
            possible_players = [p for p in players_by_rarity[rarity] if p.id not in selected_players]
            if not possible_players:
                continue  # إذا لم يتبق لاعب غير مكرر، نعيد المحاولة
            
            player = random.choice(possible_players)
            selected_players.add(player.id)  # إضافة اللاعب إلى القائمة لمنع التكرار
            
            # جلب معلومات النادي
            club_detail = ClubDetail.query.get(player.club_id) or ClubDetail.query.first()
            club_name = club_detail.club_name if club_detail else "نادي افتراضي"
            
            # إنشاء كائن لاعب للمستخدم
            user_player = UserPlayer(
                user_id=current_user.id,
                player_id=player.id,
                position=player.position,
                sale_code=generate_random_code(),
                acquired_at=datetime.utcnow()
            )
            
            db.session.add(user_player)
            
            # إضافة بيانات اللاعب إلى الرد
            players_received.append({
                'id': player.id,
                'name': player.name,
                'rating': player.rating,
                'position': player.position,
                'image_url': player.image_url,
                'rarity': player.rarity,
                'nationality': player.nationality,
                'club_name': club_name
            })
        
        # إذا لم يتم استلام أي لاعبين بسبب أخطاء
        if not players_received:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': 'حدثت مشكلة في إضافة اللاعبين. يرجى المحاولة مرة أخرى.'}), 500
        
        # تسجيل عملية شراء الباكج
        pack_purchase = PackPurchase(
            user_id=current_user.id,
            pack_id=pack.id,
            price_paid=pack.price,
            players_received=[{'player_id': p['id'], 'rarity': p['rarity']} for p in players_received]
        )
        
        db.session.add(pack_purchase)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'تم فتح الباكج بنجاح',
            'pack_name': pack.name,
            'players_received': players_received,
            'coins_remaining': current_user.coins
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error opening pack: {str(e)}")
        return jsonify({'status': 'error', 'message': f'حدث خطأ أثناء فتح الباكج: {str(e)}'}), 500


@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response


@app.route('/get_csrf_token', methods=['GET', 'OPTIONS'])
def get_csrf_token():
    if request.method == 'OPTIONS':
        return '', 200
        
    return jsonify({
        'status': 'success',
        'csrf_token': generate_csrf()
    })


#=====================   الانديه    =============================================
#=====================   الانديه    =============================================

# 📌 قاعدة URL للصور
BASE_URL_LOGO = "http://127.0.0.1:5000/static/uploads/clubs/"
BASE_URL_BANNER = "http://127.0.0.1:5000/static/uploads/clubs/bannerclub/"

# 🎯 API لاسترجاع بيانات جميع الأندية
@app.route('/api_clubs', methods=['GET'])
def api_clubs():
    try:
        # استرجاع جميع الأندية من قاعدة البيانات
        clubs = ClubDetail.query.all()

        # تحويل الأندية إلى قائمة من القواميس (dictionaries)
        club_list = []
        for club in clubs:
            club_list.append({
                'club_id': club.club_id,
                'club_name': club.club_name,
                'founded_year': club.founded_year,
                'coach_name': club.coach_name,
                'club_image_url': f"{BASE_URL_LOGO}{club.club_image_url}" if club.club_image_url else None,
                'banner_image_url': f"{BASE_URL_BANNER}{club.banner_image_url}" if club.banner_image_url else None,
                'club_color': club.club_color,
                'num_players': club.num_players,
            })

        # إرجاع الأندية على شكل JSON
        response = jsonify({
            'status': 'success',
            'clubs': club_list
        })

        
        return response, 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


#=================  اللاعبين    =====================================================
#=================  اللاعبين    =====================================================


# 🌟 API لاسترجاع اللاعبين الذين يمتلكهم المستخدم
@app.route('/api/user_players', methods=['GET'])
@jwt_required()  # ✅ تأمين الوصول باستخدام JWT
def get_user_players():
    try:
        # ✅ استخراج هوية المستخدم من التوكن
        user_id = get_jwt_identity()

        # ✅ جلب اللاعبين الذين يمتلكهم المستخدم
        user_players = UserPlayer.query.filter_by(user_id=user_id).all()

        if not user_players:
            return jsonify({
                "status": "error",
                "message": "لم يتم العثور على لاعبين لهذا المستخدم"
            }), 404

        # ✅ تجهيز بيانات اللاعبين لإرسالها كـ JSON
        players_list = []
        for user_player in user_players:
            player = user_player.player  # جلب بيانات اللاعب من الجدول Player
            club = player.club  # جلب بيانات النادي
            
            players_list.append({
                "user_player_id": user_player.id,
                "player_id": player.id,
                "name": player.name,
                "rating": player.rating,
                "position": player.position,
                "image_url": f"http://127.0.0.1:5000/static/uploads/image_player/{player.image_url}" if player.image_url else None,
                "rarity": player.rarity,
                "rarity_arabic": get_rarity_label(player.rarity),  # ترجمة الندرة
                "nationality": player.nationality,
                "club_name": club.club_name if club else "نادي غير معروف",
                "club_logo": f"http://127.0.0.1:5000/static/uploads/club_logo/{club.club_image_url}" if club and club.club_image_url else None,
                "acquired_at": user_player.acquired_at.strftime("%Y-%m-%d %H:%M:%S"),
                "is_listed": user_player.is_listed,
                "price": user_player.price,
            })

        return jsonify({
            "status": "success",
            "players": players_list
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"حدث خطأ أثناء جلب اللاعبين: {str(e)}"
        }), 500


# ✅ دالة ترجمة الندرة إلى العربية
def get_rarity_label(rarity):
    translations = {
        "common": "عادي",
        "rare": "نادر",
        "epic": "أسطوري",
        "legendary": "خارق"
    }
    return translations.get(rarity, "غير معروف")



# 🎯 API لتوليد اللاعبين من فئة معينة مرة واحدة يوميًا
@app.route('/api_generate_players', methods=['POST'])
@jwt_required()  # ✅ تأمين الوصول باستخدام JWT
def generate_daily_players():
    try:
        user_id = get_jwt_identity()  # الحصول على معرف المستخدم من التوكن
        current_user = User.query.get(user_id)

        if not current_user:
            return jsonify({'status': 'error', 'message': 'المستخدم غير موجود'}), 401

        # ✅ تأكد من أن الطلب يحتوي على JSON، وإذا لم يحتوي استخدم القيم الافتراضية
        request_data = request.get_json(silent=True) or {}

        rarity = request_data.get("rarity", "common")  # الفئة المطلوبة، الافتراضي "common"
        num_players = 3  # ✅ تحديد عدد اللاعبين المستخرجين بـ 3 فقط

        # ✅ التحقق مما إذا كان المستخدم قد حصل على لاعبين بالفعل اليوم
        last_generated = GeneratedPlayer.query.filter_by(user_id=user_id, rarity=rarity).order_by(
            GeneratedPlayer.generated_at.desc()).first()

        if last_generated and last_generated.generated_at.date() == datetime.utcnow().date():
            return jsonify({
                'status': 'error',
                'message': 'لقد حصلت بالفعل على اللاعبين اليوم، حاول مرة أخرى غدًا'
            }), 400

        # ✅ جلب اللاعبين من الفئة المطلوبة عشوائيًا
        available_players = Player.query.filter_by(rarity=rarity).all()

        if not available_players:
            return jsonify({'status': 'error', 'message': 'لا يوجد لاعبين متاحين من هذه الفئة'}), 404

        selected_players = random.sample(available_players, min(num_players, len(available_players)))

        # ✅ تخزين وقت التوليد في جدول GeneratedPlayer
        new_entry = GeneratedPlayer(user_id=user_id, rarity=rarity, generated_at=datetime.utcnow())
        db.session.add(new_entry)

        # ✅ إضافة اللاعبين إلى جدول UserPlayer
        players_data = []
        for player in selected_players:
            user_player = UserPlayer(
                user_id=user_id,
                player_id=player.id,
                position=player.position,
                is_listed=False,
                price=0,
                sale_code=generate_random_code()  # ✅ تأكد من أن هذه الدالة معرفة في مكان آخر
            )
            db.session.add(user_player)

            players_data.append({
                "id": player.id,
                "name": player.name,
                "rating": player.rating,
                "position": player.position,
                "image_url": f"http://127.0.0.1:5000/static/uploads/image_player/{player.image_url}" if player.image_url else None,
                "rarity": player.rarity,
                "nationality": player.nationality,
                "club_name": player.club.club_name if player.club else "Unknown Club"
            })

        db.session.commit()  # ✅ تنفيذ جميع التغييرات دفعة واحدة

        return jsonify({'status': 'success', 'players': players_data}), 200

    except Exception as e:
        db.session.rollback()  # ✅ التراجع عن أي تغييرات عند حدوث خطأ
        print(f"❌ خطأ في API: {str(e)}")  # ✅ طباعة الخطأ في السيرفر
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/add_to_catalog', methods=['POST'])
@jwt_required()  # ✅ تأمين الوصول باستخدام JWT
def add_to_catalog():
    try:
        # ✅ استخراج هوية المستخدم من التوكن
        user_id = get_jwt_identity()
        data = request.get_json()
        player_id = data.get('player_id')

        if not player_id:
            return jsonify({"status": "error", "message": "يجب تحديد معرف اللاعب"}), 400

        # ✅ التأكد أن اللاعب موجود في `UserPlayer`
        user_player = UserPlayer.query.filter_by(user_id=user_id, player_id=player_id).first()

        if not user_player:
            return jsonify({"status": "error", "message": "هذا اللاعب غير مملوك للمستخدم"}), 403

        # ✅ جلب النادي الخاص باللاعب
        player = Player.query.get(player_id)
        if not player or not player.club_id:
            return jsonify({"status": "error", "message": "اللاعب لا ينتمي إلى أي نادٍ"}), 404

        # ✅ التحقق مما إذا كان اللاعب موجودًا بالفعل في الكتالوج
        existing_entry = UserClub.query.filter_by(user_id=user_id, player_id=player_id).first()
        if existing_entry:
            return jsonify({"status": "error", "message": "اللاعب مضاف بالفعل إلى الكتالوج"}), 409

        # ✅ إضافة اللاعب إلى `UserClub`
        new_entry = UserClub(user_id=user_id, player_id=player_id, club_id=player.club_id)
        db.session.add(new_entry)

        # ✅ حذف اللاعب من `UserPlayer` بعد الإضافة
        db.session.delete(user_player)

        db.session.commit()

        return jsonify({"status": "success", "message": "تمت إضافة اللاعب إلى الكتالوج بنجاح"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": f"حدث خطأ: {str(e)}"}), 500




@app.route('/api/user_club_players', methods=['GET'])
@jwt_required()  # ✅ تأمين الوصول باستخدام JWT
def get_user_club_players():
    try:
        # ✅ استخراج هوية المستخدم من التوكن
        user_id = get_jwt_identity()

        # ✅ جلب اللاعبين الذين أضافهم المستخدم إلى الكتالوج
        user_club_players = UserClub.query.filter_by(user_id=user_id).all()

        if not user_club_players:
            return jsonify({
                "status": "error",
                "message": "لم يتم العثور على لاعبين في الكتالوج لهذا المستخدم"
            }), 404

        # ✅ تجهيز بيانات اللاعبين مع بيانات الأندية
        clubs_dict = {}

        for entry in user_club_players:
            player = Player.query.get(entry.player_id)
            club = ClubDetail.query.get(entry.club_id)

            if not player or not club:
                continue

            club_data = {
                "club_id": club.club_id,
                "club_name": club.club_name,
                "club_logo": f"http://127.0.0.1:5000/static/uploads/club_logo/{club.club_image_url}" if club.club_image_url else None,
                "players": []
            }

            player_data = {
                "player_id": player.id,
                "name": player.name,
                "rating": player.rating,
                "position": player.position,
                "image_url": f"http://127.0.0.1:5000/static/uploads/image_player/{player.image_url}" if player.image_url else None,
                "rarity": player.rarity,
                "rarity_arabic": get_rarity_label(player.rarity),
                "nationality": player.nationality
            }

            # ✅ تصنيف اللاعبين حسب أنديتهم
            if club.club_id not in clubs_dict:
                clubs_dict[club.club_id] = club_data

            clubs_dict[club.club_id]["players"].append(player_data)

        return jsonify({
            "status": "success",
            "clubs": list(clubs_dict.values())
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"حدث خطأ أثناء جلب اللاعبين المضافين إلى الكتالوج: {str(e)}"
        }), 500



@app.route('/api/release_player', methods=['POST'])
@jwt_required()  # ✅ تأمين الوصول باستخدام JWT
def release_player():
    try:
        # ✅ استخراج هوية المستخدم من التوكن
        user_id = get_jwt_identity()
        data = request.get_json()
        player_id = data.get('player_id')

        if not player_id:
            return jsonify({"status": "error", "message": "يجب تحديد معرف اللاعب"}), 400

        # ✅ التأكد أن اللاعب مملوك لهذا المستخدم
        user_player = UserPlayer.query.filter_by(user_id=user_id, player_id=player_id).first()

        if not user_player:
            return jsonify({"status": "error", "message": "هذا اللاعب غير موجود or لا تملكه"}), 404

        # ✅ حذف اللاعب من جدول `user_players`
        db.session.delete(user_player)
        db.session.commit()

        return jsonify({"status": "success", "message": "تم التخلي عن اللاعب بنجاح"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": f"حدث خطأ: {str(e)}"}), 500


@app.route('/api/user_coins', methods=['GET'])
@jwt_required()  # ✅ تأمين الوصول باستخدام JWT
def get_user_coins():
    try:
        # ✅ استخراج معرف المستخدم من التوكن
        user_id = get_jwt_identity()

        # ✅ جلب المستخدم من قاعدة البيانات
        user = User.query.get(user_id)
        if not user:
            return jsonify({"status": "error", "message": "المستخدم غير موجود"}), 404

        # ✅ إرسال عدد العملات الحالية للمستخدم
        return jsonify({
            "status": "success",
            "coins": user.coins  # ✅ تأكد من أن جدول المستخدم يحتوي على `coins`
        }), 200

    except Exception as e:
        return jsonify({"status": "error", "message": f"حدث خطأ: {str(e)}"}), 500




@app.route('/api/admin_market_listings', methods=['GET'])
def get_admin_market_listings():
    try:
        # ✅ جلب بيانات الفلاتر من الطلب
        min_price = request.args.get('min_price', type=int)
        max_price = request.args.get('max_price', type=int)
        status = request.args.get('status', type=str)  # active, sold, expired, cancelled
        listed_after = request.args.get('listed_after', type=str)  # 2025-03-01
        listed_before = request.args.get('listed_before', type=str)

        # ✅ تجهيز استعلام SQL ديناميكي
        query = AdminMarketListing.query

        if min_price is not None:
            query = query.filter(AdminMarketListing.price >= min_price)
        if max_price is not None:
            query = query.filter(AdminMarketListing.price <= max_price)
        if status:
            query = query.filter(AdminMarketListing.status == status)
        if listed_after:
            listed_after_date = datetime.strptime(listed_after, '%Y-%m-%d')
            query = query.filter(AdminMarketListing.listed_at >= listed_after_date)
        if listed_before:
            listed_before_date = datetime.strptime(listed_before, '%Y-%m-%d')
            query = query.filter(AdminMarketListing.listed_at <= listed_before_date)

        listings = query.all()

        # ✅ تجهيز البيانات لإرسالها إلى العميل
        listings_data = []
        for listing in listings:
            player = Player.query.get(listing.player_id)
            club = ClubDetail.query.get(player.club_id) if player else None

            listings_data.append({
                "listing_id": listing.id,
                "price": listing.price,
                "status": listing.status,
                "listed_at": listing.listed_at.strftime("%Y-%m-%d %H:%M:%S") if listing.listed_at else None,
                "expires_at": listing.expires_at.strftime("%Y-%m-%d %H:%M:%S") if listing.expires_at else None,
                "admin_id": listing.admin_id,

                # ✅ بيانات اللاعب كاملة
                "player": {
                    "player_id": player.id if player else None,
                    "name": player.name if player else "غير معروف",
                    "rating": player.rating if player else None,
                    "position": player.position if player else "غير محدد",
                    "image_url": f"http://127.0.0.1:5000/static/uploads/image_player/{player.image_url}" if player and player.image_url else None,
                    "rarity": player.rarity if player else "غير معروف",
                    "nationality": player.nationality if player else "غير معروف",

                    # ✅ بيانات النادي المرتبط باللاعب
                    "club_name": club.club_name if club else "نادي غير معروف",
                    "club_logo": f"http://127.0.0.1:5000/static/uploads/club_logo/{club.club_image_url}" if club and club.club_image_url else None
                }
            })

        return jsonify({
            "status": "success",
            "listings": listings_data
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"حدث خطأ أثناء جلب البيانات: {str(e)}"
        }), 500




# إعداد API Endpoint لإرجاع بيانات جميع الاشتراكات
@app.route('/api/subscriptions', methods=['GET'])
def get_subscriptions():
    subscriptions = Subscription.query.all()  # الحصول على جميع الاشتراكات من قاعدة البيانات
    result = []
    
    for subscription in subscriptions:
        # تحويل كل اشتراك إلى dict داخل الـ route مباشرة
        result.append({
            'id': subscription.id,
            'package_type': subscription.package_type,
            'package_details': subscription.package_details,
            'price': subscription.price,
            'is_outside_egypt': subscription.is_outside_egypt,
            'created_at': subscription.created_at.isoformat()  # تنسيق تاريخ الإنشاء ليكون بصيغة ISO
        })
    
    return jsonify(result)



# Route لتسجيل طلب شراء اشتراك


@app.route('/api/purchase_subscription', methods=['POST'])
def purchase_subscription():
    try:
        # استقبال البيانات من الطلب
        data = request.get_json()
        
        # التحقق من وجود الحقول المطلوبة
        if not data or 'user_id' not in data or 'subscription_id' not in data:
            return jsonify({'success': False, 'message': 'البيانات المطلوبة غير موجودة'}), 400
        
        user_id = data['user_id']
        subscription_id = data['subscription_id']
        status = data.get('status', 'active')

        # التحقق مما إذا كان المستخدم لديه اشتراك نشط بالفعل
        existing_subscription = UserSubscriptionPurchase.query.filter_by(
            user_id=user_id,
            status='active'
        ).first()

        if existing_subscription:
            return jsonify({
                'success': False,
                'message': 'المستخدم مشترك بالفعل في الخدمة'
            }), 400

        # حساب تاريخ انتهاء الاشتراك (بعد شهر من الآن)
        purchase_date = datetime.utcnow()
        expiry_date = purchase_date + timedelta(days=30)

        # إنشاء سجل جديد في الجدول مع تاريخ الانتهاء
        purchase = UserSubscriptionPurchase(
            user_id=user_id,
            subscription_id=subscription_id,
            status=status,
            purchase_date=purchase_date,
            expiry_date=expiry_date
        )
        
        # إضافة السجل وحفظه في قاعدة البيانات
        db.session.add(purchase)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'تم تسجيل طلب الشراء بنجاح',
            'data': {
                'id': purchase.id,
                'user_id': purchase.user_id,
                'subscription_id': purchase.subscription_id,
                'purchase_date': purchase.purchase_date.isoformat(),
                'expiry_date': purchase.expiry_date.isoformat(),
                'status': purchase.status
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'حدث خطأ: {str(e)}'}), 500

# دالة للتحقق من الاشتراكات المنتهية وحذفها or تعطيلها
def check_expired_subscriptions():
    try:
        current_time = datetime.utcnow()
        expired_subscriptions = UserSubscriptionPurchase.query.filter(
            UserSubscriptionPurchase.expiry_date <= current_time,
            UserSubscriptionPurchase.status == 'active'
        ).all()

        for subscription in expired_subscriptions:
            # يمكنك اختيار حذف الاشتراك or تعطيله
            #subscription.status = 'expired'  # تغيير الحالة إلى منتهي
            # or حذف الاشتراك تمامًا:
             db.session.delete(subscription)

        db.session.commit()
        print(f"تم تحديث {len(expired_subscriptions)} اشتراك منتهي")
    except Exception as e:
        db.session.rollback()
        print(f"خطأ أثناء التحقق من الاشتراكات المنتهية: {str(e)}")

# لتشغيل التحقق التلقائي، يمكنك استخدام scheduler مثل APScheduler
scheduler = BackgroundScheduler()
scheduler.add_job(check_expired_subscriptions, 'interval', hours=24)  # يتم التحقق كل 24 ساعة
scheduler.start()



#=================  اللاعبين    =====================================================
#=================  اللاعبين    =====================================================


@app.route('/')
def home():
    try:
        # جلب البيانات المطلوبة للصفحة الرئيسية
        available_packs = Pack.query.filter_by(is_active=True).all()
        subscription = Subscription.query.all()
        
        # التحقق من حالة تسجيل الدخول وجلب بيانات المستخدم
        is_authenticated = False
        user_coins = 0
        can_open_daily = False
        daily_pack_end_timestamp = None
        is_subscribed = False

        if current_user.is_authenticated:
            is_authenticated = True
            user_coins = current_user.coins

            # التحقق من إمكانية فتح الباكج اليومي
            last_daily = GeneratedPlayer.query.filter_by(user_id=current_user.id)\
                .order_by(GeneratedPlayer.generated_at.desc())\
                .first()
                
            if last_daily:
                time_since_last = datetime.utcnow() - last_daily.generated_at
                if time_since_last < timedelta(days=1):
                    can_open_daily = False
                    time_remaining = timedelta(days=1) - time_since_last
                    daily_pack_end_timestamp = (datetime.utcnow() + time_remaining).timestamp()
                else:
                    can_open_daily = True
            else:
                can_open_daily = True

            # التحقق من حالة الاشتراك
            active_subscription = UserSubscriptionPurchase.query.filter_by(
                user_id=current_user.id,
                status='active'
            ).first()
            is_subscribed = bool(active_subscription)
        

    except Exception as e:
        app.logger.error(f"Error in home route: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'حدث خطأ أثناء تحميل الصفحة'
        }), 500
    
    return render_template('site/index.html',
                            user={
                                'is_authenticated': is_authenticated,
                                'coins': user_coins,
                                'is_subscribed': is_subscribed
                            },
                            available_packs=available_packs,
                            can_open_daily=can_open_daily,
                            daily_pack_end_timestamp=daily_pack_end_timestamp,
                            subscription=subscription)


@app.route('/profile')
@login_required
def profile():
    try:
        # حساب عدد اللاعبين في الكتالوج للمستخدم
        catalog_count = UserClub.query.filter_by(user_id=current_user.id).count()
        
        # حساب إجمالي اللاعبين المملوكين
        owned_count = UserPlayer.query.filter_by(user_id=current_user.id).count()
        
        # حساب الترتيب العام
        all_users = db.session.query(
            User.id,
            User.username,
            func.count(UserClub.id).label('catalog_count')
        ).outerjoin(UserClub).group_by(User.id).order_by(desc('catalog_count')).all()
        
        # تحديد ترتيب المستخدم
        user_rank = next((index + 1 for (index, user) in enumerate(all_users) 
                         if user.id == current_user.id), 0)
        
        # الحصول على المتسابقين القريبين (3 أعلى و3 أسفل)
        nearby_users = []
        if user_rank > 0:
            start_idx = max(0, user_rank - 4)
            end_idx = min(len(all_users), user_rank + 3)
            nearby_users = all_users[start_idx:end_idx]
        
        # خيارات شحن المحفظة
        wallet_options = [
            {'amount': 100, 'price': 20, 'description': '100 عملة'},
            {'amount': 500, 'price': 90, 'description': '500 عملة'},
            {'amount': 1000, 'price': 170, 'description': '1000 عملة'},
            {'amount': 2000, 'price': 300, 'description': '2000 عملة'},
        ]
        
        # طرق الدفع
        payment_methods = [
            {'id': 'vodafone', 'name': 'فودافون كاش', 'icon': 'vodafone.png'},
            {'id': 'etisalat', 'name': 'اتصالات كاش', 'icon': 'etisalat.png'},
            {'id': 'orange', 'name': 'اورانج كاش', 'icon': 'orange.png'},
            {'id': 'we', 'name': 'وي باي', 'icon': 'we.png'},
        ]

        return render_template('site/profile.html',
                            user=current_user,
                            catalog_count=catalog_count,
                            owned_count=owned_count,
                            user_rank=user_rank,
                            nearby_users=nearby_users,
                            wallet_options=wallet_options,
                            payment_methods=payment_methods)

    except Exception as e:
        app.logger.error(f"Error in profile route: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'حدث خطأ أثناء تحميل الصفحة'
        }), 500
        

        
# إضافة route للتعامل مع طلبات شحن المحفظة
@app.route('/recharge-wallet', methods=['POST'])
@login_required
def recharge_wallet():
    try:
        data = request.get_json()
        amount = data.get('amount')
        payment_method = data.get('payment_method')
        
        # هنا يمكن إضافة المنطق الخاص بمعالجة الدفع
        # مثل التواصل مع بوابة الدفع الإلكتروني
        
        return jsonify({
            'status': 'success',
            'message': 'تم إرسال طلب الشحن بنجاح'
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/myplayers')
@login_required
def myplayers():
    try:
        # تصحيح استعلام قاعدة البيانات باستخدام select_from وjoin بشكل صحيح
        user_players = db.session.query(
            UserPlayer,
            Player.name,
            Player.rating,
            Player.position,
            Player.image_url,
            Player.rarity,
            Player.nationality,
            ClubDetail.club_name,
            ClubDetail.club_image_url
        ).select_from(UserPlayer)\
        .join(Player, UserPlayer.player_id == Player.id)\
        .join(ClubDetail, Player.club_id == ClubDetail.club_id)\
        .filter(UserPlayer.user_id == current_user.id)\
        .all()

        # حساب الأسعار المقترحة حسب الندرة
        price_ranges = {
            'common': (20, 50),
            'rare': (51, 100),
            'epic': (101, 150),
            'legendary': (151, 200)
        }

        players_data = []
        for (user_player, name, rating, position, image_url, 
             rarity, nationality, club_name, club_logo) in user_players:
            
            min_price, max_price = price_ranges.get(rarity, (20, 50))
            suggested_price = int(rating * (max_price / 100))
            
            players_data.append({
                'id': user_player.id,
                'player_id': user_player.player_id,
                'name': name,
                'rating': rating,
                'position': position,
                'image_url': image_url,
                'rarity': rarity,
                'nationality': nationality,
                'club_name': club_name,
                'club_logo': club_logo,
                'suggested_price': suggested_price,
                'sale_code': user_player.sale_code
            })

        return render_template('site/myplayers.html', 
                            players=players_data,
                            user=current_user)

    except Exception as e:
        app.logger.error(f"Error in myplayers route: {str(e)}")
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': 'حدث خطأ أثناء تحميل الصفحة'
        }), 500

@app.route('/collect_player', methods=['POST'])
@login_required
def collect_player():
    try:
        data = request.get_json()
        if not data or 'playerData' not in data:
            return jsonify({
                'status': 'error',
                'message': 'بيانات غير صحيحة'
            }), 400

        player_data = data['playerData']
        player_id = player_data.get('id')
        user_player_id = player_data.get('user_player_id')

        if not player_id or not user_player_id:
            return jsonify({
                'status': 'error',
                'message': 'معرف اللاعب غير موجود'
            }), 400

        # التحقق من وجود اللاعب في قاعدة البيانات
        player = Player.query.get(player_id)
        if not player:
            return jsonify({
                'status': 'error',
                'message': 'اللاعب غير موجود'
            }), 404

        # التحقق من وجود اللاعب في الكتالوج
        existing_in_catalog = UserClub.query.filter_by(
            user_id=current_user.id,
            player_id=player_id
        ).first()

        if existing_in_catalog:
            return jsonify({
                'status': 'warning',
                'message': 'هذا اللاعب موجود بالفعل في الكتالوج'
            }), 409

        # التحقق من أن المستخدم يمتلك اللاعب
        user_player = UserPlayer.query.filter_by(
            id=user_player_id,
            user_id=current_user.id,
            player_id=player_id
        ).first()

        if not user_player:
            return jsonify({
                'status': 'error',
                'message': 'أنت لا تمتلك هذا اللاعب'
            }), 403

        # إضافة اللاعب إلى كتالوج المستخدم
        try:
            user_club = UserClub(
                user_id=current_user.id,
                player_id=player_id,
                club_id=player.club_id
            )
            db.session.add(user_club)
            db.session.delete(user_player)
            db.session.commit()

            return jsonify({
                'status': 'success',
                'message': 'تم إضافة اللاعب للكتالوج بنجاح',
                'player_id': player_id
            }), 200

        except Exception as e:
            db.session.rollback()
            raise e

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in collect_player: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/sell_player', methods=['POST'])
@login_required
def sell_player():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'بيانات غير صحيحة'
            }), 400

        player_id = data.get('player_id')
        user_player_id = data.get('user_player_id')
        price = data.get('price', 0)

        if not player_id or not user_player_id:
            return jsonify({
                'status': 'error',
                'message': 'معرف اللاعب غير موجود'
            }), 400

        # التحقق من وجود اللاعب وملكية المستخدم له
        user_player = UserPlayer.query.filter_by(
            id=user_player_id,
            user_id=current_user.id,
            player_id=player_id
        ).first()

        if not user_player:
            return jsonify({
                'status': 'error',
                'message': 'اللاعب غير موجود أو غير مملوك لك'
            }), 404

        # إضافة العملات للمستخدم
        current_user.coins += price
        
        # حذف اللاعب
        db.session.delete(user_player)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'تم بيع اللاعب بنجاح وإضافة العملات لحسابك',
            'new_balance': current_user.coins,
            'player_id': player_id
        }), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in sell_player: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500



@app.route('/open_package/<int:pack_id>', methods=['POST', 'OPTIONS'])
@csrf.exempt
def open_package(pack_id):
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        # التحقق من تسجيل الدخول
        if not current_user.is_authenticated:
            return jsonify({'status': 'error', 'message': 'يجب تسجيل الدخول للوصول إلى هذه الصفحة'}), 401

        # التحقق من الباكج
        pack = Pack.query.get_or_404(pack_id)
        
        if not pack.is_active:
            return jsonify({'status': 'error', 'message': 'هذا الباكج غير متاح حالياً'}), 400
        
        if current_user.coins < pack.price:
            return jsonify({'status': 'error', 'message': 'ليس لديك عملات كافية لفتح هذا الباكج'}), 400
        
        # جلب جميع اللاعبين المتاحين
        all_players = Player.query.all()
        
        if not all_players:
            return jsonify({'status': 'error', 'message': 'لا يوجد لاعبين في النظام. يرجى المحاولة لاحقاً.'}), 404
        
        # خصم العملات
        current_user.coins -= pack.price
        
        # تصنيف اللاعبين حسب الندرة
        players_by_rarity = {
            'common': [p for p in all_players if p.rarity == 'common'],
            'rare': [p for p in all_players if p.rarity == 'rare'],
            'epic': [p for p in all_players if p.rarity == 'epic'],
            'legendary': [p for p in all_players if p.rarity == 'legendary']
        }
        
        # التحقق من توفر اللاعبين لكل ندرة
        missing_rarities = [r for r, c in pack.rarity_odds.items() if c > 0 and not players_by_rarity.get(r, [])]
        
        if missing_rarities:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': f'لا يوجد لاعبين من الفئات التالية: {", ".join(missing_rarities)}. يرجى المحاولة لاحقاً.'}), 404
        
        # اختيار اللاعبين
        selected_players = set()
        players_received = []

        while len(players_received) < pack.player_count:
            available_rarities = [r for r in pack.rarity_odds.keys() if pack.rarity_odds[r] > 0 and players_by_rarity.get(r, [])]
            
            if not available_rarities:
                break
            
            weights = [pack.rarity_odds[r] for r in available_rarities]
            rarity = random.choices(population=available_rarities, weights=weights, k=1)[0]
            
            possible_players = [p for p in players_by_rarity[rarity] if p.id not in selected_players]
            if not possible_players:
                continue
            
            player = random.choice(possible_players)
            selected_players.add(player.id)
            
            club_detail = ClubDetail.query.get(player.club_id) or ClubDetail.query.first()
            club_name = club_detail.club_name if club_detail else "نادي افتراضي"
            
            user_player = UserPlayer(
                user_id=current_user.id,
                player_id=player.id,
                position=player.position,
                sale_code=generate_random_code(),
                acquired_at=datetime.utcnow()
            )
            
            db.session.add(user_player)
            
            players_received.append({
                'id': player.id,
                'name': player.name,
                'rating': player.rating,
                'position': player.position,
                'image_url': player.image_url,
                'rarity': player.rarity,
                'nationality': player.nationality,
                'club_name': club_name
            })
        
        if not players_received:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': 'حدثت مشكلة في إضافة اللاعبين. يرجى المحاولة مرة أخرى.'}), 500
        
        # تسجيل عملية شراء الباكج
        pack_purchase = PackPurchase(
            user_id=current_user.id,
            pack_id=pack.id,
            price_paid=pack.price,
            players_received=[{'player_id': p['id'], 'rarity': p['rarity']} for p in players_received]
        )
        
        db.session.add(pack_purchase)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'تم فتح الباكج بنجاح',
            'pack_name': pack.name,
            'players_received': players_received,
            'coins_remaining': current_user.coins
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error opening package: {str(e)}")
        return jsonify({'status': 'error', 'message': f'حدث خطأ أثناء فتح الباكج: {str(e)}'}), 500



# 🎯 API لتوليد اللاعبين من فئة معينة مرة واحدة يوميًا
@app.route('/generate_daily_pack', methods=['POST'])
@login_required
def generate_daily_pack():
    try:
        # Check if user already generated today
        last_generated = GeneratedPlayer.query.filter_by(user_id=current_user.id)\
            .order_by(GeneratedPlayer.generated_at.desc()).first()

        if last_generated and last_generated.generated_at.date() == datetime.utcnow().date():
            return jsonify({
                'status': 'error',
                'message': 'لقد حصلت بالفعل على اللاعبين اليوم، حاول مرة أخرى غدًا'
            }), 400

        # Get random common players
        rarity = "common"
        num_players = 3
        available_players = Player.query.filter_by(rarity=rarity).all()

        if not available_players:
            return jsonify({'status': 'error', 'message': 'لا يوجد لاعبين متاحين من هذه الفئة'}), 404

        selected_players = random.sample(available_players, min(num_players, len(available_players)))

        # Record generation time
        new_entry = GeneratedPlayer(
            user_id=current_user.id,
            rarity=rarity,
            generated_at=datetime.utcnow()
        )
        db.session.add(new_entry)

        # Add players to user's collection
        players_data = []
        for player in selected_players:
            user_player = UserPlayer(
                user_id=current_user.id,
                player_id=player.id,
                position=player.position,
                is_listed=False,
                price=0,
                sale_code=generate_random_code()
            )
            db.session.add(user_player)

            players_data.append({
                "id": player.id,
                "name": player.name,
                "rating": player.rating,
                "position": player.position,
                "image_url": player.image_url,  # Just the filename
                "rarity": player.rarity,
                "nationality": player.nationality,
                "club_name": player.club.club_name if player.club else "Unknown Club"
            })

        db.session.commit()
        return jsonify({'status': 'success', 'players': players_data}), 200

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error in generate_daily_pack: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/market')
@login_required
def market():
    try:
        # Query active market listings and join player and club details
        listings_query = AdminMarketListing.query.filter(AdminMarketListing.status=='active').all()
        listings = []
        for listing in listings_query:
            player = listing.player
            club = player.club if player else None
            listings.append({
                'listing_id': listing.id,
                'price': listing.price,
                'listed_at': listing.listed_at.strftime("%Y-%m-%d %H:%M:%S") if listing.listed_at else "",
                'expires_at': listing.expires_at.strftime("%Y-%m-%d %H:%M:%S") if listing.expires_at else "",
                'player': {
                    'id': player.id,
                    'name': player.name,
                    'rating': player.rating,
                    'position': player.position,
                    'image_url': player.image_url,
                    'rarity': player.rarity,
                    'nationality': player.nationality
                },
                'club': {
                    'club_name': club.club_name if club else "",
                    'club_image_url': club.club_image_url if club else ""
                }
            })
        return render_template('site/market.html', 
                            listings=listings,
                            user={'is_authenticated': True, 'coins': current_user.coins},
                            username=current_user.username)
    except Exception as e:
        app.logger.error(f"Error in market route: {str(e)}")
        flash('حدث خطأ أثناء تحميل صفحة السوق', 'error')
        return redirect(url_for('index'))
