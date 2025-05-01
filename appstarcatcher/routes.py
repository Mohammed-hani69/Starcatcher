from datetime import time, timedelta
import random
import json
from flask_jwt_extended import create_access_token, create_refresh_token, decode_token, get_jwt_identity, jwt_required
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from numpy import identity
import requests
from sqlalchemy import desc, func, text

# Define base URLs for images
BASE_URL_LOGO = 'http://127.0.0.1:5000/static/uploads/clubs/'
BASE_URL_BANNER = 'http://127.0.0.1:5000/static/uploads/clubs/bannerclub/'
BASE_URL_PLAYERS = 'http://127.0.0.1:5000/static/uploads/image_player/'
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from appstarcatcher import db , app ,limiter,csrf
from flask import jsonify, logging, render_template, request, redirect, session, url_for, flash
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
from appstarcatcher.forms import AdminMarketListingForm, ClubForm, LoginForm, PackForm, PlayerForm, PromotionForm, RegistrationForm, SubscriptionForm
from appstarcatcher.models import AdminMarketListing, Beneficiary, ClubDetail, GeneratedPlayer, Pack, PackPurchase, Player, Promotion, Subscription, Transaction, User, UserClub, UserPlayer, UserSubscriptionPurchase, PaymentMethod, WalletRechargeOption, generate_random_code
from appstarcatcher.utils.image_handler import save_image, delete_image
from appstarcatcher.models import WalletRechargeRequest
import uuid

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

# إضافة ثابت لمجلد صور وسائل الدفع
app.config['UPLOAD_FOLDER_PAYMENT_METHODS'] = 'appstarcatcher/static/uploads/payment_methods'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#=======================================================================================================================
#=======================================================================================================================

def permission_required(permission):
    """ديكوريتر للتحقق مما إذا كان لدى المستخدم صلاحية معينة"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                if request.is_json or request.method in ['POST', 'DELETE', 'PUT']:
                    return jsonify({"message": "يجب عليك تسجيل الدخول أولاً."}), 401
                flash("يجب عليك تسجيل الدخول أولاً.", "warning")
                return redirect(url_for('login'))

            # التحقق من أن المستخدم مسؤول أو لديه الصلاحية المطلوبة
            if not (current_user.is_admin or getattr(current_user, permission, False)):
                if request.is_json or request.method in ['POST', 'DELETE', 'PUT']:
                    return jsonify({"message": "ليس لديك الصلاحيات الكافية."}), 403
                flash("ليس لديك الصلاحية للوصول إلى هذه الصفحة.", "danger")
                return redirect(url_for('home'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

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
    if (current_user.is_authenticated):
        if (current_user.is_admin):
            return redirect(url_for('dashboard'))
        return redirect(url_for('home'))
    form = LoginForm()
    if (form.validate_on_submit()):
        # تنظيف البيانات المدخلة
        email = form.email.data.lower().strip()
        password_hash = form.password.data
        try:
            user = User.query.filter_by(email=email).first()
            if (user and user.check_password(password_hash)):
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
                if (user.is_admin):
                    flash('تم تسجيل الدخول بنجاح!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('تم تسجيل الدخول بنجاح!', 'success')
                    return redirect(url_for('home'))
            else:
                # زيادة عدد محاولات تسجيل الدخول الفاشلة
                if user:
                    user.login_attempts = ((user.login_attempts or 0) + 1)
                    if (user.login_attempts >= 5):  # قفل الحساب بعد 5 محاولات فاشلة
                        user.is_locked = True
                        user.locked_until = (datetime.utcnow() + timedelta(minutes=30))
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
@permission_required('can_manage_dashboard')
def dashboard():
    try:
        # تحقق إضافي من الجلسة
        if not current_user.is_authenticated:
            return redirect(url_for('login'))

        if not (current_user.is_admin or current_user.can_manage_dashboard):
            flash('ليس لديك صلاحية الوصول إلى لوحة التحكم', 'error')
            return redirect(url_for('home'))

        form = PackForm()
        formmarket = AdminMarketListingForm()
        packs = Pack.query.filter_by(is_active=True).all()
        listings = AdminMarketListing.query.filter(
            (AdminMarketListing.expires_at > datetime.utcnow())
        ).join(Player).all()
        
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
                'player_image_url': listing.player.image_url,
                'expires_at': listing.expires_at.isoformat(),
                'status': listing.status
            })

        csrf_token_value = generate_csrf()
        count_player = Player.query.count()
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
        return redirect(url_for('home'))

# التعامل مع محاولات الوصول غير المصرح به
@app.errorhandler(401)
def unauthorized(error):
    flash('يجب تسجيل الدخول للوصول إلى هذه الصفحة', 'error')
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden(error):
    flash('غير مصرح لك بالوصول إلى هذه الصفحة', 'error')
    return redirect(url_for('index'))

from flask import jsonify
from flask_login import current_user, login_required

@app.route('/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
def toggle_admin(user_id):
    """ تبديل حالة الأدمن مع تحديث جميع الصلاحيات الأخرى """
    if not current_user.is_admin:
        return jsonify({'message': 'غير مصرح لك بهذا الإجراء'}), 403

    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        return jsonify({'message': 'لا يمكنك تغيير صلاحياتك الخاصة'}), 403

    try:
        # تبديل حالة الأدمن
        user.is_admin = not user.is_admin
        
        # تحديث جميع الصلاحيات بناءً على حالة الأدمن الجديدة
        all_permissions = [
            'can_manage_users',
            'can_manage_dashboard',
            'can_manage_players',
            'can_manage_clubs',
            'can_manage_packs',
            'can_manage_market',
            'can_manage_subscriptions',
            'can_manage_promotions'
        ]
        
        # إذا كان المستخدم أدمن، يتم تفعيل كل الصلاحيات، وإلا يتم إلغاؤها
        for perm in all_permissions:
            setattr(user, perm, user.is_admin)

        db.session.commit()
        
        message = f"تم {'منح' if user.is_admin else 'إلغاء'} صلاحيات الأدمن وجميع الصلاحيات الأخرى للمستخدم {user.username}"
        return jsonify({'success': True, 'message': message, 'is_admin': user.is_admin})

    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'حدث خطأ أثناء تحديث الصلاحيات'}), 500


@app.route('/update_profile_image', methods=['POST'])
@login_required
@csrf.exempt
def update_profile_image():
    try:
        if ('image' not in request.files):
            return jsonify({'status': 'error', 'message': 'لم يتم تحديد صورة'}), 400
        file = request.files['image']
        if (file.filename == ''):
            return jsonify({'status': 'error', 'message': 'لم يتم اختيار صورة'}), 400
        if file:
            # حفظ الصورة الجديدة مع التحسين
            filename = f"profile_{current_user.id}_{int(time.time())}"
            new_filename = save_image(file, app.config['UPLOAD_FOLDER'], filename)
            if (not new_filename):
                return jsonify({'status': 'error', 'message': 'فشل في معالجة الصورة'}), 400
            # حذف الصورة القديمة إذا وجدت
            if current_user.image_url:
                delete_image(current_user.image_url, app.config['UPLOAD_FOLDER'])
            # تحديث قاعدة البيانات
            current_user.image_url = new_filename
            db.session.commit()
            return jsonify({'status': 'success', 'message': 'تم تحديث وتحسين الصورة بنجاح', 'image_url': url_for('static', filename=f'uploads/profile_images/{new_filename}')})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'حدث خطأ أثناء تحديث الصورة: {str(e)}'}), 500

@app.route('/collect_achievement_coins', methods=['POST'])
@login_required
@csrf.exempt
def collect_achievement_coins():
    try:
        # التحقق مما إذا كان المستخدم قد جمع هذه المكافأة من قبل
        if current_user.new_member_reward_collected:
            return jsonify({'status': 'error', 'message': 'تم تحصيل هذه المكافأة مسبقاً'}), 400
        # إضافة العملات للمستخدم
        current_user.coins += 50
        # تحديث حالة تحصيل المكافأة
        current_user.new_member_reward_collected = True
        # حفظ التغييرات في قاعدة البيانات
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'تم تحصيل 50 عملة بنجاح!', 'new_balance': current_user.coins})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/collect_first_purchase_reward', methods=['POST'])
@login_required
@csrf.exempt
def collect_first_purchase_reward():
    try:
        if (not current_user.first_purchase_reward_collected):
            # إضافة العملات للمستخدم
            current_user.coins += 60
            # تحديث حالة تحصيل المكافأة
            current_user.first_purchase_reward_collected = True
            db.session.commit()
            return jsonify({'status': 'success', 'message': 'تم تحصيل 60 عملة بنجاح!', 'new_balance': current_user.coins})
        else:
            return jsonify({'status': 'error', 'message': 'تم تحصيل هذه المكافأة مسبقاً'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500



@app.route('/collect_referral_earnings', methods=['POST'])
@csrf.exempt
@login_required
def collect_referral_earnings():
    user = current_user
    if not user.referral_earnings or user.referral_earnings <= 0:
        return jsonify({'status': 'error', 'message': 'No earnings to collect'})
    
    try:
        earnings = user.referral_earnings
        user.coins = user.coins + earnings
        user.referral_earnings = 0
        user.referral_earnings_collected = True
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'Successfully collected {earnings} coins',
            'new_balance': user.coins
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'Failed to collect earnings'})



@app.route('/api/purchase_subscription', methods=['POST'])
@login_required
@csrf.exempt
def purchase_subscription():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
            
        subscription_id = data.get('subscription_id')
        if not subscription_id:
            return jsonify({'success': False, 'message': 'Subscription ID is required'}), 400

        # 🔹 قفل السجل لمنع التكرار
        existing_subscription = UserSubscriptionPurchase.query.filter_by(
            user_id=current_user.id,
            status='expired'
        ).with_for_update().first()

        if existing_subscription:
            return jsonify({
                'success': False, 
                'message': 'You already have an active subscription'
            }), 400

        subscription = Subscription.query.get(subscription_id)
        if not subscription:
            return jsonify({'success': False, 'message': 'Invalid subscription'}), 404

        payment_method = data.get('payment_method')
        if not payment_method:
            return jsonify({'success': False, 'message': 'Payment method is required'}), 400

        purchase_date = datetime.utcnow()
        expiry_date = purchase_date + timedelta(days=30)

        # 🔹 إنشاء الاشتراك
        purchase = UserSubscriptionPurchase(
            user_id=current_user.id,
            subscription_id=subscription.id,
            payment_method=payment_method,
            price=subscription.price,
            username=current_user.username,
            email=current_user.email,
            country=current_user.country,
            status='expired',
            purchase_date=purchase_date,
            expiry_date=expiry_date,
            payment_link=subscription.payment_link

        )
        
        db.session.add(purchase)
        
        # 🔹 تحديث حالة المستخدم
        current_user.subscription = True
        current_user.type_subscription = subscription.package_type.lower()

        

        # 🔹 تعيين الشارات - تم نقلها إلى apply_subscription_benefits
        db.session.commit()

        
        return jsonify({
            'success': True,
            'message': 'تم طلب الاشتراك بنجاح',
            'data': {
                'type_subscription': subscription.package_type,
                'expiry_date': expiry_date.isoformat(),
                'coins_reward': subscription.coins_reward,
                'new_balance': current_user.coins
            }
        })

    except IntegrityError as e:
        db.session.rollback()
        app.logger.error(f"Integrity error in purchase_subscription: {str(e)}")
        return jsonify({
            'success': False, 
            'message': 'هذا الاشتراك موجود مسبقاً'
        }), 400

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in purchase_subscription: {str(e)}")
        return jsonify({
            'success': False, 
            'message': 'حدث خطأ أثناء عملية الشراء، الرجاء المحاولة مرة أخرى'
        }), 500



@app.route('/subscription_purchases')
@login_required
@permission_required('can_manage_users')
def subscription_purchases():
    try:
        # Get subscription purchases with related data
        purchases = db.session.query(
            UserSubscriptionPurchase,
            Subscription,
            User
        ).join(
            Subscription,
            UserSubscriptionPurchase.subscription_id == Subscription.id
        ).join(
            User,
            UserSubscriptionPurchase.user_id == User.id
        ).all()

        # Calculate analytics data
        total_sales = len(purchases)
        active_subscriptions = sum(1 for p in purchases if p[0].status == 'active')

        # Calculate revenues separately for Egypt and outside Egypt
        revenue_egypt = sum(p[0].price for p in purchases 
                          if p[0].country == 'eg')
        revenue_outside = sum(p[0].price for p in purchases 
                            if p[0].country != 'eg')
        total_revenue = revenue_egypt + revenue_outside
        
        # Calculate growth percentages (comparing to previous month)
        previous_month = datetime.utcnow() - timedelta(days=30)
        current_month_sales = sum(1 for p in purchases if p[0].purchase_date >= previous_month)
        previous_month_sales = sum(1 for p in purchases if previous_month - timedelta(days=30) <= p[0].purchase_date < previous_month)
        
        sales_growth = round(((current_month_sales - previous_month_sales) / previous_month_sales * 100) if previous_month_sales > 0 else 0, 1)
        active_percentage = round((active_subscriptions / total_sales * 100) if total_sales > 0 else 0, 1)
        
        # Calculate conversion rate (active subscriptions / total purchases)
        conversion_rate = round((active_subscriptions / total_sales * 100) if total_sales > 0 else 0, 1)

        purchase_data = []
        for purchase, subscription, user in purchases:
            purchase_data.append({
                'id': purchase.id,
                'user': user,
                'subscription': subscription,
                'payment_method': purchase.payment_method,
                'price': purchase.price,
                'username': purchase.username,
                'email': purchase.email,
                'country': purchase.country,
                'status': purchase.status,
                'purchase_date': purchase.purchase_date,
                'expiry_date': purchase.expiry_date
            })

        # Get data for charts
        # 1. Sales Trend Data (last 6 months)
        months = []
        sales_data = []
        for i in range(5, -1, -1):
            date = datetime.utcnow() - timedelta(days=i*30)
            month_start = date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            month_end = (month_start + timedelta(days=32)).replace(day=1) - timedelta(seconds=1)
            
            month_sales = db.session.query(UserSubscriptionPurchase).filter(
                UserSubscriptionPurchase.purchase_date.between(month_start, month_end)
            ).count()
            
            months.append(date.strftime('%B'))  # Month name
            sales_data.append(month_sales)

        # 2. Package Distribution Data
        package_distribution = db.session.query(
            Subscription.package_type,
            func.count(UserSubscriptionPurchase.id)
        ).join(
            UserSubscriptionPurchase
        ).group_by(
            Subscription.package_type
        ).all()

        package_labels = []
        package_data = []
        for pkg_type, count in package_distribution:
            package_labels.append(pkg_type)
            package_data.append(count)

        # 3. Payment Methods Data
        payment_methods = db.session.query(
            UserSubscriptionPurchase.payment_method,
            func.count(UserSubscriptionPurchase.id)
        ).group_by(
            UserSubscriptionPurchase.payment_method
        ).all()

        payment_labels = []
        payment_data = []
        for method, count in payment_methods:
            payment_labels.append(method)
            payment_data.append(count)

        # حساب المبيعات حسب الدولة
        sales_by_country = db.session.query(
            UserSubscriptionPurchase.country,
            func.count(UserSubscriptionPurchase.id).label('count')
        ).group_by(
            UserSubscriptionPurchase.country
        ).all()

        # تحضير البيانات للعرض
        country_labels = []
        country_data = []
        country_map = {
            'eg': 'مصر',
            'sa': 'السعودية',
            'ae': 'الإمارات',
            'jo': 'الأردن'
        }

        other_countries_count = 0
        for country, count in sales_by_country:
            if country in country_map:
                country_labels.append(country_map[country])
                country_data.append(count)
            else:
                other_countries_count += count
        
        if other_countries_count > 0:
            country_labels.append('دول أخرى')
            country_data.append(other_countries_count)

        return render_template(
            'subscription_purchases.html',
            purchases=purchase_data,
            username=current_user.username,
            total_sales=total_sales,
            active_subscriptions=active_subscriptions,
            total_revenue=total_revenue,
            revenue_egypt=revenue_egypt,
            revenue_outside=revenue_outside,
            sales_growth=sales_growth,
            active_percentage=active_percentage,
            revenue_growth=sales_growth, # Using same growth for revenue for simplicity
            conversion_rate=conversion_rate,
            # Chart data
            months=months,
            sales_data=sales_data,
            package_labels=package_labels,
            package_data=package_data,
            payment_labels=payment_labels,
            payment_data=payment_data,
            country_labels=country_labels,
            country_data=country_data
        )
    except Exception as e:
        app.logger.error(f"Error in subscription_purchases route: {str(e)}")
        flash('حدث خطأ أثناء تحميل صفحة المشتريات', 'error')
        return redirect(url_for('dashboard'))





# إنشاء باكج جديد
@app.route('/packs', methods=['POST'])
@csrf.exempt  # إضافة استثناء CSRF
@permission_required('can_manage_packs')
def create_pack():
    if (request.method == 'POST'):
        try:
            # التحقق من البيانات المستلمة
            form_data = request.form
            file = request.files.get('image')
            # معالجة الصورة إذا تم تحميلها
            image_url = None
            if (file and file.filename):
                filename = secure_filename(file.filename)  # تأكيد الاسم الآمن
                filepath = os.path.join(app.config['UPLOAD_FOLDER_PACKS'], filename)  # تحديد المسار الكامل
                file.save(filepath)  # حفظ الصورة في المجلد
                image_url = f'{filename}'  # المسار الذي سيتم عرضه للمستخدم
            # تجميع نسب النادرية
            rarity_odds = {'common': int(form_data.get('rarity_common', 70)), 'rare': int(form_data.get('rarity_rare', 20)), 'epic': int(form_data.get('rarity_epic', 8)), 'legendary': int(form_data.get('rarity_legendary', 2))}
            # إنشاء باكج جديد
            new_pack = Pack(name=form_data['name'], description=form_data['description'], price=int(form_data['price']), player_count=int(form_data['player_count']), image_url=image_url, rarity_odds=rarity_odds, is_active=bool(form_data.get('is_active', True)))
            # حفظ الباكج في قاعدة البيانات
            db.session.add(new_pack)
            db.session.commit()
            # إرجاع استجابة JSON
            return jsonify({'status': 'success', 'message': 'تم إضافة الباكج بنجاح', 'pack': {'id': new_pack.id, 'name': new_pack.name, 'price': new_pack.price, 'image_url': new_pack.image_url}}), 201
        except Exception as e:
            # إرجاع استجابة خطأ في حالة حدوث مشكلة
            db.session.rollback()
            return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/update_user_coins/<int:user_id>', methods=['POST'])
@login_required
@permission_required('can_manage_users')
def update_user_coins(user_id):
    try:
        data = request.get_json()
        amount = data.get('amount', 0)
        # التحقق من وجود المستخدم
        user = User.query.get(user_id)
        if (not user):
            return jsonify({'status': 'error', 'message': 'المستخدم غير موجود'}), 404
        # التحقق من صحة القيمة
        if (not isinstance(amount, (int, float))):
            return jsonify({'status': 'error', 'message': 'قيمة غير صحيحة للعملات'}), 400
        # التأكد من أن الرصيد لن يصبح سالباً
        new_balance = (user.coins + amount)
        if (new_balance < 0):
            return jsonify({'status': 'error', 'message': 'لا يمكن أن يكون رصيد العملات سالباً'}), 400
        # تحديث قيمة العملات
        user.coins = new_balance
        db.session.commit()
        return jsonify({'status': 'success', 'message': f'تم تحديث رصيد العملات بنجاح', 'new_balance': new_balance})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'حدث خطأ أثناء تحديث العملات: {str(e)}'}), 500

@app.route('/set_user_coins/<int:user_id>', methods=['POST'])
@login_required
@permission_required('can_manage_users')
def set_user_coins(user_id):
    try:
        data = request.get_json()
        new_coins = data.get('coins', 0)
        # التحقق من وجود المستخدم
        user = User.query.get(user_id)
        if (not user):
            return jsonify({'status': 'error', 'message': 'المستخدم غير موجود'}), 404
        # التحقق من صحة القيمة
        if ((not isinstance(new_coins, (int, float))) or (new_coins < 0)):
            return jsonify({'status': 'error', 'message': 'قيمة غير صحيحة للعملات'}), 400
        # تحديث قيمة العملات
        user.coins = new_coins
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'تم تحديث رصيد العملات بنجاح', 'new_balance': new_coins})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'حدث خطأ أثناء تحديث العملات: {str(e)}'}), 500

@app.route('/add_to_collection', methods=['POST'])
@login_required
@csrf.exempt
def add_to_collection():
    try:
        data = request.get_json()
        player_id = data.get('player_id')
        user_player_id = data.get('user_player_id')
        if (not player_id or (not user_player_id)):
            return jsonify({'success': False, 'message': 'معرف اللاعب غير موجود'}), 400
        # Get the player from UserPlayer
        user_player = UserPlayer.query.filter_by(id=user_player_id, user_id=current_user.id).first()
        if (not user_player):
            return jsonify({'success': False, 'message': 'اللاعب غير موجود'}), 404
        # Get player details
        player = Player.query.get(player_id)
        if (not player):
            return jsonify({'success': False, 'message': 'معلومات اللاعب غير موجودة'}), 404
        # Create new UserClub entry
        new_club_entry = UserClub(user_id=current_user.id, club_id=player.club_id, player_id=player_id)
        # Remove from UserPlayer and add to UserClub
        db.session.add(new_club_entry)
        db.session.delete(user_player)
        db.session.commit()
        return jsonify({'success': True, 'message': 'تم إضافة اللاعب للكتالوج بنجاح', 'image_url': player.image_url, 'player_name': player.name})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'حدث خطأ: {str(e)}'}), 500

#==================================  حذف الباكج

# حذف باكج
@app.route('/packs/<int:pack_id>', methods=['DELETE'])
@csrf.exempt  # إضافة استثناء CSRF
@permission_required('can_manage_packs')
def delete_pack(pack_id):
    try:
        if (not current_user.is_authenticated or (not current_user.is_admin)):
            return jsonify({'status': 'error', 'message': 'غير مصرح لك بحذف الباكجات'}), 403
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
        return jsonify({'status': 'success', 'message': 'تم حذف الباكج وكل البيانات المرتبطة به بنجاح'}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting pack: {str(e)}")
        return jsonify({'status': 'error', 'message': f'حدث خطأ أثناء حذف الباكج: {str(e)}'}), 500

@app.route('/catalog')
@login_required
def catalog():
    # تعديل الاستعلام لإرجاع كائنات ClubDetail بدلاً من Row objects
    clubs = db.session.query(ClubDetail).all()
    # تجهيز بيانات الأندية بشكل صحيح
    clubs_data = []
    for club in clubs:
        clubs_data.append({'club_id': club.club_id, 'club_name': club.club_name, 'club_color': club.club_color, 'club_image_url': (url_for('static', filename=f'uploads/clubs/{club.club_image_url}') if club.club_image_url else None)})
    return render_template('catalog/index.html', clubs=clubs_data)

@app.route('/catalog/<int:club_id>')
@login_required
def club_catalog(club_id):
    try:
        club = ClubDetail.query.get_or_404(club_id)
        # Get all players in the club
        club_players = Player.query.filter_by(club_id=club_id).order_by(Player.position, Player.rating.desc()).all()
        # Get collected players
        collected_players = db.session.query(UserClub).filter(UserClub.user_id == current_user.id, UserClub.club_id == club_id).all()
        # Get user's uncollected players from UserPlayer
        user_players = db.session.query(UserPlayer).filter(UserPlayer.user_id == current_user.id).all()
        # Create sets for easier lookup
        collected_ids = {cp.player_id for cp in collected_players}
        user_player_map = {up.player_id: up.id for up in user_players}
        # Organize squad by position
        squad = {}
        positions = {p.position for p in club_players}
        for position in positions:
            position_players = [p for p in club_players if (p.position == position)]
            squad[position] = [{'id': p.id, 'name': p.name, 'position': position, 'rating': p.rating, 'image_url': (p.image_url if (p.id in collected_ids) else None), 'rarity': p.rarity, 'is_collected': (p.id in collected_ids), 'is_collectible': (p.id in user_player_map), 'user_player_id': user_player_map.get(p.id)} for p in position_players]
        total_players = len(club_players)
        collected_count = len(collected_ids)
        completion_percentage = ((collected_count / total_players) * 100) if (total_players > 0) else 0
        return render_template('catalog/club.html', club=club, squad=squad, total_players=total_players, collected_count=collected_count, completion_percentage=completion_percentage)
    except Exception as e:
        app.logger.error(f"Error in club_catalog: {str(e)}")
        flash('حدث خطأ أثناء تحميل الكتالوج', 'error')
        return redirect(url_for('catalog'))

@app.route('/get_club_players/<int:club_id>')
@login_required
def get_club_players(club_id):
    players = Player.query.filter_by(club_id=club_id).all()
    collected = UserClub.query.filter_by(user_id=current_user.id, club_id=club_id).with_entities(UserClub.player_id).all()
    collected_ids = [c.player_id for c in collected]
    return jsonify({'players': [{'id': p.id, 'name': p.name, 'position': p.position, 'image_url': (p.image_url if (p.id in collected_ids) else None), 'is_collected': (p.id in collected_ids)} for p in players]})

@app.route('/users')
@login_required
@permission_required('can_manage_users')
def users():
    try:
        # Get rankings for all users based on player count first
        user_rankings = db.session.query(
            User,
            func.count(UserClub.id).label('player_count'),
            func.dense_rank().over(order_by=func.count(UserClub.id).desc()).label('rank'),
            func.max(UserSubscriptionPurchase.id).label('user_subscription_purchases_id'),
            func.max(UserSubscriptionPurchase.user_id).label('user_subscription_purchases_user_id'),
            func.max(UserSubscriptionPurchase.subscription_id).label('user_subscription_purchases_subscription_id'),
            func.max(UserSubscriptionPurchase.payment_method).label('user_subscription_purchases_payment_method'),
            func.max(UserSubscriptionPurchase.price).label('user_subscription_purchases_price'),
            func.max(UserSubscriptionPurchase.username).label('user_subscription_purchases_username'),
            func.max(UserSubscriptionPurchase.email).label('user_subscription_purchases_email'),
            func.max(UserSubscriptionPurchase.country).label('user_subscription_purchases_country'),
            func.max(UserSubscriptionPurchase.status).label('user_subscription_purchases_status'),
            func.max(UserSubscriptionPurchase.purchase_date).label('user_subscription_purchases_purchase_date'),
            func.max(UserSubscriptionPurchase.expiry_date).label('user_subscription_purchases_expiry_date')
        ).outerjoin(UserClub).outerjoin(UserSubscriptionPurchase, db.and_(
            User.id == UserSubscriptionPurchase.user_id, 
            UserSubscriptionPurchase.status == 'active'
        )).group_by(User.id).all()

        # Get subscription details
        subscription_details = {}
        for record in user_rankings:
            user = record[0]
            subscription_id = record[5]  # user_subscription_purchases_subscription_id
            expiry_date = record[13]     # user_subscription_purchases_expiry_date
            
            if subscription_id:
                subscription_info = Subscription.query.get(subscription_id)
                subscription_details[user.id] = {
                    'package_type': (subscription_info.package_type if subscription_info else None),
                    'expiry_date': expiry_date
                }

        # Separate admins and regular users while preserving their ranks
        admin_users = []
        regular_users = []
        for record in user_rankings:
            user = record[0]
            player_count = record[1]
            rank = record[2]
            
            user_data = {
                'user': user, 
                'player_count': player_count, 
                'rank': rank, 
                'subscription_info': subscription_details.get(user.id, None)
            }
            
            if user.is_admin:
                admin_users.append(user_data)
            else:
                regular_users.append(user_data)

        # Combine the lists with admins at the top
        users_data = (admin_users + regular_users)
        return render_template('users.html', users=users_data, username=current_user.username)

    except Exception as e:
        app.logger.error(f"Error in users route: {str(e)}")
        flash('حدث خطأ أثناء تحميل صفحة المستخدمين', 'error')
        return redirect(url_for('dashboard'))


@app.route('/add_listing', methods=['POST'])
@login_required
@permission_required('can_manage_market')
def add_listing():
    try:
        if (not request.is_json):
            return jsonify({'status': 'error', 'message': 'نوع الطلب غير صحيح'}), 400
        data = request.get_json()
        # التحقق من وجود الحقول المطلوبة
        required_fields = ['player_id', 'price', 'expires_at', 'status']
        for field in required_fields:
            if (field not in data):
                return jsonify({'status': 'error', 'message': f'الحقل {field} مطلوب'}), 400
        # التحقق من وجود اللاعب
        player = Player.query.get(data.get('player_id'))
        if (not player):
            return jsonify({'status': 'error', 'message': 'اللاعب غير موجود'}), 404
        # التحقق من أن اللاعب ليس مدرجًا بالفعل في السوق
        existing_listing = AdminMarketListing.query.filter(AdminMarketListing.player_id == player.id, AdminMarketListing.expires_at > datetime.utcnow()).first()
        if existing_listing:
            return jsonify({'status': 'error', 'message': 'اللاعب مدرج بالفعل في السوق'}), 400
        try:
            expires_at = datetime.strptime(data['expires_at'], '%Y-%m-%dT%H:%M')
        except ValueError:
            return jsonify({'status': 'error', 'message': 'صيغة التاريخ غير صحيحة'}), 400
        if (expires_at <= datetime.utcnow()):
            return jsonify({'status': 'error', 'message': 'تاريخ الانتهاء يجب أن يكون في المستقبل'}), 400
        # إنشاء القائمة الجديدة
        new_listing = AdminMarketListing(player_id=player.id, price=int(data['price']), expires_at=expires_at, status=data['status'], listed_at=datetime.utcnow(), admin_id=current_user.id)
        db.session.add(new_listing)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'تم إضافة اللاعب إلى السوق بنجاح', 'listing': {'id': new_listing.id, 'player_id': new_listing.player_id, 'price': new_listing.price, 'expires_at': new_listing.expires_at.isoformat(), 'status': new_listing.status}}), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in add_listing: {str(e)}")
        return jsonify({'status': 'error', 'message': 'حدث خطأ أثناء إضافة اللاعب للسوق'}), 500

@app.route('/get_players')
@login_required
def get_players():
    try:
        # جلب جميع اللاعبين بدون فلتر is_active
        players = Player.query.all()
        if (not players):
            app.logger.warning('لا يوجد لاعبين')
            return jsonify({'status': 'success', 'players': []})
        return jsonify({'status': 'success', 'players': [{'id': p.id, 'name': p.name, 'rating': p.rating, 'position': p.position} for p in players]})
    except Exception as e:
        app.logger.error(f'Error in get_players: {str(e)}')
        return jsonify({'status': 'error', 'message': 'حدث خطأ أثناء جلب قائمة اللاعبين'}), 500

@app.route('/delete-player-market/<int:id>', methods=['DELETE'])
@permission_required('can_manage_market')
def delete_player_market(id):
    # تأكد من طباعة المعرّف للتحقق
    print(f"Attempting to delete player with ID: {id}")
    try:
        player = AdminMarketListing.query.get(id)
        if (player is None):
            return jsonify({"message": "اللاعب غير موجود"}), 404
        db.session.delete(player)
        db.session.commit()
        return jsonify({"message": "تم الحذف بنجاح"}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting player: {str(e)}")
        return jsonify({"message": "حدث خطأ أثناء الحذف", "error": str(e)}), 500

@app.route('/add_player', methods=['GET', 'POST'])
@login_required
@permission_required('can_manage_players')
def add_player():

    # ✅ التحقق مما إذا كان المستخدم لديه صلاحية "إدارة اللاعبين"
    if not current_user.can_manage_players:
        flash("ليس لديك صلاحية لإضافة لاعبين.", "danger")
        return redirect(url_for('dashboard')) 
    
    form = PlayerForm()
    clubs = ClubDetail.query.order_by(ClubDetail.club_name).all()
    form.club.choices = [(club.club_id, club.club_name) for club in clubs]  # استخدام club_id
    if (form.validate_on_submit()):
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
                characters = (string.ascii_uppercase + string.ascii_lowercase + string.digits)
                while True:
                    # إنشاء كود عشوائي
                    code = ''.join(random.choice(characters) for _ in range(length))
                    # التحقق من أن الكود غير موجود في أسماء الصور الحالية
                    existing_images = [f for f in os.listdir(app.config['UPLOAD_FOLDER_IMAGE_PLAYER']) if os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER_IMAGE_PLAYER'], f))]
                    if (not any((code in img_name) for img_name in existing_images)):
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
        player = Player(name=form.name.data, rating=form.rating.data, position=form.position.data, image_url=image_path, rarity=form.rarity.data, nationality=form.nationality.data, club_id=club.club_id)  # تعيين club_id بدلاً من club
        db.session.add(player)
        db.session.commit()
        flash('تم إضافة اللاعب بنجاح بعد إزالة الخلفية!', 'success')
        return redirect(url_for('add_player'))
    players = Player.query.order_by(Player.rating.desc()).all()
    username = current_user.username
    return render_template('add_player.html', form=form, players=players, username=username)

@app.route('/delete_player/', methods=['DELETE'])
@permission_required('can_manage_players')
def delete_player():
    try:
        data = request.get_json()
        if (not data or ('player_id' not in data)):
            return jsonify({'error': 'معرّف اللاعب مطلوب'}), 400
        player_id = data['player_id']
        player = Player.query.get_or_404(player_id)
        db.session.delete(player)
        db.session.commit()
        return jsonify({'message': 'تم حذف اللاعب بنجاح'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'حدث خطأ أثناء حذف اللاعب'}), 500


@app.route('/update_player', methods=['POST'])
@login_required
def update_player():
    try:
        # التعامل مع البيانات من الـ FormData
        player_id = request.form.get('player_id')
        player = Player.query.get(player_id)
        
        if not player:
            return jsonify({'success': False, 'message': 'لم يتم العثور على اللاعب'}), 404

        # تحديث بيانات اللاعب
        player.name = request.form.get('name')
        player.rating = request.form.get('rating')
        player.position = request.form.get('position')
        player.nationality = request.form.get('nationality')
        # تحديث النادي بشكل صحيح
        club_name = request.form.get('club')
        club = ClubDetail.query.filter_by(club_name=club_name).first()
        if club:
            player.club_id = club.club_id
        player.rarity = request.form.get('rarity')

        # معالجة الصورة إذا تم تحديثها
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename:
                try:
                    # حذف الصورة القديمة إذا وجدت
                    if player.image_url:
                        old_image_path = os.path.join(app.config['UPLOAD_FOLDER_IMAGE_PLAYER'], player.image_url)
                        if os.path.exists(old_image_path):
                            os.remove(old_image_path)

                    # حفظ الصورة الجديدة
                    filename = secure_filename(file.filename)
                    unique_code = generate_random_code()
                    new_filename = f"{os.path.splitext(filename)[0]}_{unique_code}_no_bg.png"
                    
                    # حفظ الصورة مؤقتاً
                    temp_path = os.path.join(app.config['UPLOAD_FOLDER_IMAGE_PLAYER'], filename)
                    file.save(temp_path)

                    # إزالة الخلفية
                    with open(temp_path, "rb") as img_file:
                        input_image = img_file.read()
                        output_image = remove(input_image)

                    # حفظ الصورة النهائية بدون خلفية
                    final_path = os.path.join(app.config['UPLOAD_FOLDER_IMAGE_PLAYER'], new_filename)
                    with open(final_path, "wb") as img_file:
                        img_file.write(output_image)

                    # حذف الصورة المؤقتة
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                    
                    # تحديث مسار الصورة في قاعدة البيانات
                    player.image_url = new_filename

                except Exception as img_error:
                    app.logger.error(f"Error processing image: {str(img_error)}")
                    return jsonify({
                        'success': False,
                        'message': 'حدث خطأ أثناء معالجة الصورة'
                    }), 500

        db.session.commit()
        return jsonify({
            'success': True, 
            'message': 'تم تحديث بيانات اللاعب بنجاح',
            'player': {
                'id': player.id,
                'name': player.name,
                'rating': player.rating,
                'position': player.position,
                'nationality': player.nationality,
                'club': club_name if club else '',
                'rarity': player.rarity,
                'image_url': player.image_url
            }
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating player: {str(e)}")
        return jsonify({
            'success': False, 
            'message': f'حدث خطأ أثناء التحديث: {str(e)}'
        }), 500



@app.route('/error')
def error_page():
    error_msg = session.get('error_message', 'حدث خطأ غير متوقع')
    error_code = session.get('error_code', 500)
    return render_template('error.html', error_message=error_msg, error_code=error_code)


@app.route('/api/toggle-subscription-status', methods=['POST'])
@login_required
@permission_required('can_manage_subscriptions')
@csrf.exempt
def toggle_subscription_status():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'message': 'بيانات غير صالحة'
            }), 400

        user_id = data.get('user_id')
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'معرف المستخدم مطلوب'
            }), 400

        is_active = int(data.get('is_active', 0))

        # التحقق من وجود المستخدم
        user = User.query.get(int(user_id))
        if not user:
            return jsonify({
                'success': False,
                'message': 'المستخدم غير موجود'
            }), 404

        # البحث عن آخر اشتراك للمستخدم
        subscription_purchase = UserSubscriptionPurchase.query.filter_by(
            user_id=int(user_id)
        ).order_by(UserSubscriptionPurchase.purchase_date.desc()).first()

        if subscription_purchase:
            # تحديث حالة الاشتراك في كلا الجدولين
            old_status = subscription_purchase.status
            new_status = 'active' if is_active else 'expired'
            
            subscription_purchase.status = new_status
            user.subscription = bool(is_active)

            # فقط في حالة التحول من expired إلى active نطبق المزايا
            if old_status == 'expired' and new_status == 'active':
                success = apply_subscription_benefits(user.id, subscription_purchase.subscription_id)
                if not success:
                    db.session.rollback()
                    return jsonify({
                        'success': False, 
                        'message': 'حدث خطأ أثناء تطبيق مزايا الاشتراك، الرجاء المحاولة مرة أخرى'
                    }), 500

                # ✅ تطبيق العمولة إن وُجد مُحيل وكان من المستفيدين
                if user.referred_by:
                    referrer = User.query.filter_by(referral_code=user.referred_by).first()
                    if referrer and referrer.email:
                        beneficiary = Beneficiary.query.filter_by(email=referrer.email, is_active=True).first()
                        if beneficiary and beneficiary.is_active == True:
                            commission_rate = beneficiary.commission_rate or 0
                            commission_amount = (subscription_purchase.price * commission_rate) / 100.0
                            referrer.earned_money += commission_amount
                            app.logger.info(
                                f"أُضيفت عمولة {commission_amount:.2f} للمستخدم {referrer.username} "
                                f"من اشتراك المستخدم {user.username}"
                            )

            db.session.commit()

            status_text = "تم تفعيل الاشتراك" if is_active else "تم إلغاء تفعيل الاشتراك"
            return jsonify({
                'success': True,
                'message': status_text,
                'old_status': old_status,
                'new_status': new_status,
                'subscription_status': subscription_purchase.status
            })
        else:
            return jsonify({
                'success': False,
                'message': 'لا يوجد اشتراك لهذا المستخدم'
            }), 404

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in toggle_subscription_status: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'حدث خطأ: {str(e)}'
        }), 500




@app.route('/add_club', methods=['GET', 'POST'])
@login_required
@permission_required('can_manage_clubs')
def add_club():
    form = ClubForm()
    if (form.validate_on_submit()):
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
        new_club = ClubDetail(club_name=form.club_name.data, founded_year=form.founded_year.data, coach_name=form.coach_name.data, club_image_url=club_image_url, banner_image_url=banner_image_filename, num_players=form.num_players.data, club_color=club_color)  # اللون
        db.session.add(new_club)
        db.session.commit()
        flash('تم إضافة النادي بنجاح!', 'success')
        return redirect(url_for('add_club'))
    clubs = ClubDetail.query.all()
    username = current_user.username
    return render_template('add_club.html', form=form, clubs=clubs, username=username)

@app.route('/delete_club/<int:club_id>', methods=['DELETE'])
@permission_required('can_manage_clubs')
def delete_club(club_id):
    try:
        # طباعة رسالة تشخيص
        print(f"Attempting to delete club with ID: {club_id}")
        # البحث عن النادي
        club = ClubDetail.query.get(club_id)
        if (club is None):
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
        return jsonify({"message": "حدث خطأ أثناء الحذف", "error": str(e)}), 500

@app.route('/edit_club/<int:club_id>', methods=['POST'])
@csrf.exempt
@permission_required('can_manage_clubs')
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
        if ('edit_club_image' in request.files):
            club_image = request.files['edit_club_image']
            if (club_image and club_image.filename):
                filename = secure_filename(club_image.filename)
                club_image.save(os.path.join(app.config['UPLOAD_FOLDER_CLUB'], filename))
                club.club_image_url = filename
        if ('edit_banner_image' in request.files):
            banner_image = request.files['edit_banner_image']
            if (banner_image and banner_image.filename):
                banner_filename = secure_filename(banner_image.filename)
                banner_image.save(os.path.join(app.config['UPLOAD_FOLDER_BANNERCLUBS'], banner_filename))
                club.banner_image_url = banner_filename
        db.session.commit()
        return jsonify({'success': True, 'message': 'تم تحديث بيانات النادي بنجاح'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'حدث خطأ أثناء تحديث بيانات النادي'}), 500

@app.route('/get_club/<int:club_id>')
def get_club(club_id):
    try:
        club = ClubDetail.query.get_or_404(club_id)
        return jsonify({'club_name': club.club_name, 'coach_name': club.coach_name, 'founded_year': club.founded_year, 'num_players': club.num_players, 'club_color': club.club_color, 'club_image_url': (club.club_image_url or ''), 'banner_image_url': (club.banner_image_url or '')})
    except Exception as e:
        return jsonify({'error': 'النادي غير موجود'}), 404

@app.route('/add_subscription', methods=['GET', 'POST'])
@login_required
@permission_required('can_manage_subscriptions')
def add_subscription():
    form = SubscriptionForm()
    if form.validate_on_submit():
        # إضافة اشتراك جديد مع جميع الحقول
        subscription = Subscription(
            package_type=form.package_type.data,
            package_details=form.package_details.data,
            price=form.price.data,
            is_outside_egypt=form.is_outside_egypt.data,
            coins_reward=form.coins_reward.data,
            daily_free_packs=form.daily_free_packs.data,
            joker_players=form.joker_players.data,
            has_vip_badge=form.has_vip_badge.data,
            has_vip_badge_plus=form.has_vip_badge_plus.data,
            subscription_achievement_coins=form.subscription_achievement_coins.data,
            allow_old_ahly_catalog=form.allow_old_ahly_catalog.data,
            payment_link=form.payment_link.data,
            payment_link_usd=form.payment_link_usd.data,
        )
        # إضافة الاشتراك إلى قاعدة البيانات
        db.session.add(subscription)
        db.session.commit()
        flash('تم إضافة الاشتراك بنجاح!', 'success')
        return redirect(url_for('add_subscription'))  # إعادة التوجيه إلى نفس الصفحة
    subscriptions = Subscription.query.all()  # استرجاع جميع الاشتراكات
    return render_template('add_subscription.html', form=form, subscriptions=subscriptions, username=current_user.username)


@app.route('/delete_subscription/<int:id>', methods=['DELETE'])
@csrf.exempt  
@permission_required('can_manage_subscriptions')
def delete_subscription(id):
    if not request.is_json:
        return jsonify({"status": "error", "message": "Content-Type must be application/json"}), 400
    
    try:
        subscription = Subscription.query.get(id)
        if subscription is None:
            return jsonify({"status": "error", "message": "الاشتراك غير موجود"}), 404

        # التحقق من وجود اشتراكات نشطة لهذه الباقة
        active_subscriptions = UserSubscriptionPurchase.query.filter_by(
            subscription_id=id,
            status='active'
        ).first()

        if active_subscriptions:
            return jsonify({
                "status": "error", 
                "message": "لا يمكن حذف هذه الباقة لوجود مشتركين نشطين فيها"
            }), 400

        db.session.delete(subscription)
        db.session.commit()
        return jsonify({"status": "success", "message": "تم الحذف بنجاح"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error", 
            "message": "حدث خطأ أثناء الحذف", 
            "error": str(e)
        }), 500

@app.route('/buy_market_player', methods=['POST'])
@login_required
@csrf.exempt
def buy_market_player():
    try:
        data = request.get_json()
        listing_id = data.get('listing_id')
        if (not listing_id):
            return jsonify({'status': 'error', 'message': 'معرف القائمة مطلوب'}), 400
        # التحقق من وجود القائمة
        listing = AdminMarketListing.query.get(listing_id)
        if ((not listing) or (listing.status != 'active')):
            return jsonify({'status': 'error', 'message': 'هذا العرض غير متوفر'}), 404
        # التحقق من تاريخ انتهاء العرض
        if (listing.expires_at and (listing.expires_at < datetime.utcnow())):
            return jsonify({'status': 'error', 'message': 'هذا العرض منتهي'}), 400
        # التحقق من امتلاك العملات الكافية
        if (current_user.coins < listing.price):
            return jsonify({'status': 'error', 'message': 'لا تملك عملات كافية لشراء هذا اللاعب'}), 400
        # الحصول على معلومات اللاعب
        player = Player.query.get(listing.player_id)
        if (not player):
            return jsonify({'status': 'error', 'message': 'اللاعب غير موجود'}), 404
        try:
            # إنشاء سجل جديد في UserPlayer وحفظه للحصول على الـ id
            user_player = UserPlayer(user_id=current_user.id, player_id=player.id, position=player.position, is_listed=False, price=listing.price, acquired_at=datetime.utcnow(), sale_code=generate_random_code())
            db.session.add(user_player)
            db.session.flush()  # للحصول على الـ id قبل الـ commit
            # خصم العملات من المستخدم
            current_user.coins -= listing.price
            # إنشاء سجل المعاملة بعد التأكد من وجود user_player_id
            transaction = Transaction(buyer_id=current_user.id, seller_id=listing.admin_id, user_player_id=user_player.id, listing_id=listing_id, price=listing.price, transaction_type='market', status='completed', payment_method='coins')
            db.session.add(transaction)
            # حفظ جميع التغييرات
            db.session.commit()
            # التحقق من أول عملية شراء
            is_first_purchase = (not Transaction.query.filter(Transaction.buyer_id == current_user.id, Transaction.id != transaction.id, Transaction.status == 'completed').first())
            return jsonify({'status': 'success', 'message': 'تم شراء اللاعب بنجاح', 'is_first_purchase': is_first_purchase, 'data': {'player_name': player.name, 'price_paid': listing.price, 'remaining_coins': current_user.coins, 'sale_code': user_player.sale_code}}), 200
        except Exception as e:
            db.session.rollback()
            raise e
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in buy_market_player: {str(e)}")
        return jsonify({'status': 'error', 'message': f'حدث خطأ أثناء شراء اللاعب: {str(e)}'}), 500

#=============================  API  ====================================
#=============================  API  ====================================
#=============================  API  ====================================

# رووت API للتسجيل
# دالة تهييش كلمة المرور
def hash_password(password):
    # استخدام خوارزمية pbkdf2:sha256 مع 600000 تكرار وملح عشوائي
    return generate_password_hash(password, method='pbkdf2:sha256:600000', salt_length=16)


@app.route('/api/preview_subscription_rewards', methods=['POST'])
@login_required
@csrf.exempt
def preview_subscription_rewards():
    try:
        data = request.get_json()
        subscription_id = data.get('subscription_id')
        
        if not subscription_id:
            return jsonify({
                'success': False,
                'message': 'Subscription ID is required'
            }), 400
            
        subscription = Subscription.query.get(subscription_id)
        if not subscription:
            return jsonify({
                'success': False,
                'message': 'Invalid subscription'
            }), 404

        # Generate preview players based on subscription
        preview_players = []
        if subscription.joker_players > 0:
            # Get random legendary players for preview
            legendary_players = Player.query.filter_by(rarity='legendary').all()
            if legendary_players:
                selected_players = random.sample(
                    legendary_players, 
                    min(len(legendary_players), subscription.joker_players)
                )
                
                for player in selected_players:
                    preview_players.append({
                        'id': player.id,
                        'name': player.name,
                        'rating': player.rating,
                        'position': player.position,
                        'image_url': url_for('static', 
                            filename=f'uploads/image_player/{player.image_url}'
                        ) if player.image_url else None,
                        'rarity': player.rarity,
                        'nationality': player.nationality
                    })

        return jsonify({
            'success': True,
            'rewards': {
                'coins_reward': subscription.coins_reward,
                'players': preview_players,
                'duration_days': 30,
                'daily_packs': subscription.daily_free_packs,
                'has_vip': subscription.has_vip_badge,
                'has_vip_plus': subscription.has_vip_badge_plus
            }
        })

    except Exception as e:
        app.logger.error(f"Error in preview_subscription_rewards: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while generating preview'
        }), 500

# Update the purchase_subscription route

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            # حفظ صورة الملف الشخصي إذا تم تحميلها
            image_url = None
            if form.profile_image.data:
                filename = f"profile_{datetime.utcnow().timestamp()}"
                image_file = save_image(form.profile_image.data, app.config['UPLOAD_FOLDER'], filename)
                image_url = image_file if image_file else 'default.png'
            
            # إنشاء المستخدم الجديد
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
            
            # حفظ المستخدم في قاعدة البيانات
            db.session.add(user)
            db.session.commit()

            # معالجة كود الإحالة إذا تم إدخاله
            if form.referral_code.data:
                referral_result = User.apply_referral_code(form.referral_code.data, user)
                if referral_result:
                    db.session.commit()
                    flash('تم تطبيق كود الإحالة بنجاح! تم إضافة 50 عملة إلى حسابك.', 'success')
                else:
                    flash('كود الإحالة غير صالح أو لا يمكن استخدامه.', 'warning')
            
            flash('تم إنشاء حسابك بنجاح! يمكنك تسجيل الدخول الآن.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Registration error: {str(e)}")
            flash('حدث خطأ أثناء إنشاء الحساب. الرجاء المحاولة مرة أخرى.', 'danger')
    
    return render_template('register.html', form=form)


@app.route('/get_subscription/<int:id>')
@login_required
@permission_required('can_manage_subscriptions')
def get_subscription(id):
    try:
        subscription = Subscription.query.get_or_404(id)
        return jsonify({
            'success': True,
            'subscription': {
                'id': subscription.id,
                'package_type': subscription.package_type,
                'package_details': subscription.package_details,
                'price': subscription.price,
                'coins_reward': subscription.coins_reward,
                'daily_free_packs': subscription.daily_free_packs,
                'joker_players': subscription.joker_players,
                'subscription_achievement_coins': subscription.subscription_achievement_coins,
                'has_vip_badge': subscription.has_vip_badge,
                'has_vip_badge_plus': subscription.has_vip_badge_plus,
                'allow_old_ahly_catalog': subscription.allow_old_ahly_catalog,
                'is_outside_egypt': subscription.is_outside_egypt
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/update_subscription/<int:id>', methods=['POST'])
@login_required
@permission_required('can_manage_subscriptions')
def update_subscription(id):
    try:
        subscription = Subscription.query.get_or_404(id)
        data = request.get_json()

        # تحديث البيانات
        subscription.package_type = data['package_type']
        subscription.price = data['price']
        subscription.coins_reward = data['coins_reward']
        subscription.daily_free_packs = data['daily_free_packs']
        subscription.joker_players = data['joker_players']
        subscription.subscription_achievement_coins = data['subscription_achievement_coins']
        subscription.package_details = data['package_details']
        subscription.has_vip_badge = data['has_vip_badge']
        subscription.has_vip_badge_plus = data['has_vip_badge_plus']
        subscription.allow_old_ahly_catalog = data['allow_old_ahly_catalog']
        subscription.is_outside_egypt = data['is_outside_egypt']

        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'تم تحديث الباقة بنجاح'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'حدث خطأ: {str(e)}'
        }), 500


# رووت API لتسجيل الدخول
@app.route('/api_login', methods=['POST'])
@csrf.exempt
def login_api():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if (user and verify_password(user.password_hash, password)):  # التحقق من تطابق كلمة المرور
        # When creating tokens, ensure user_id is converted to string
        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity.str(user.id))
        return jsonify({"success": True, "message": "تم تسجيل الدخول بنجاح!", "data": {"id": user.id, "username": user.username, "name": user.username, "email": email, "coins": user.coins, "token": access_token, "refresh_token": refresh_token}}), 200
    else:
        return jsonify({"success": False, "message": "البريد الإلكتروني or كلمة المرور غير صحيحة"}), 401

# رووت للتحقق من صلاحية التوكن
@app.route('/validate_token', methods=['GET'])
@jwt_required()
def validate_token():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if user:
        return jsonify({"success": True, "message": "التوكن صالح", "user_id": current_user_id}), 200
    else:
        return jsonify({"success": False, "message": "التوكن غير صالح or المستخدم غير موجود"}), 401

# رووت لتحديث التوكن
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user_id = get_jwt_identity()
    access_token = create_access_token(identity=current_user_id)
    return jsonify({"success": True, "access_token": access_token}), 200

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
            pack_list.append({'id': pack.id, 'name': pack.name, 'description': pack.description, 'image_url': pack.image_url, 'price': pack.price, 'player_count': pack.player_count, 'rarity_odds': pack.rarity_odds, 'is_active': pack.is_active, 'created_at': pack.created_at})
        # إرجاع الباكجات على شكل JSON
        return jsonify({'status': 'success', 'packs': pack_list}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/open_pack/<int:pack_id>', methods=['POST', 'OPTIONS'])
@csrf.exempt
def open_pack(pack_id):
    if (request.method == 'OPTIONS'):
        return ('', 200)
    try:
        # التحقق من التوكن والمستخدم
        auth_header = request.headers.get('Authorization')
        if (auth_header and auth_header.startswith('Bearer ')):
            token = auth_header.split(' ')[1]
            try:
                user_claims = decode_token(token)
                user_id = user_claims['sub']
                current_user = User.query.get(user_id)
                if (not current_user):
                    return jsonify({'status': 'error', 'message': 'مستخدم غير موجود'}), 401
                login_user(current_user)
            except Exception:
                return jsonify({'status': 'error', 'message': 'رمز المصادقة غير صالح'}), 401
        else:
            return jsonify({'status': 'error', 'message': 'يجب تسجيل الدخول للوصول إلى هذه الصفحة'}), 401
        # التحقق من الباكج
        pack = Pack.query.get_or_404(pack_id)
        if (not pack.is_active):
            return jsonify({'status': 'error', 'message': 'هذا الباكج غير متاح حالياً'}), 400
        if (current_user.coins < pack.price):
            return jsonify({'status': 'error', 'message': 'ليس لديك عملات كافية لفتح هذا الباكج'}), 400
        # جلب جميع اللاعبين المتاحين
        all_players = Player.query.all()
        if (not all_players):
            return jsonify({'status': 'error', 'message': 'لا يوجد لاعبين في النظام. يرجى المحاولة لاحقاً.'}), 404
        # خصم العملات
        current_user.coins -= pack.price
        # تصنيف اللاعبين حسب الندرة
        players_by_rarity = {'common': [p for p in all_players if (p.rarity == 'common')], 'rare': [p for p in all_players if (p.rarity == 'rare')], 'epic': [p for p in all_players if (p.rarity == 'epic')], 'legendary': [p for p in all_players if (p.rarity == 'legendary')]}
        # التحقق من توفر اللاعبين لكل ندرة
        missing_rarities = []
        for (rarity, count) in pack.rarity_odds.items():
            if ((count > 0) and (not players_by_rarity.get(rarity, []))):
                missing_rarities.append(rarity)
        if missing_rarities:
            db.session.rollback()  # إلغاء خصم العملات
            return jsonify({'status': 'error', 'message': f'لا يوجد لاعبين من الفئات التالية: {", ".join(missing_rarities)}. يرجى المحاولة لاحقاً.'}), 404
        # قائمة لتتبع اللاعبين المضافين ومنع التكرار
        selected_players = set()
        players_received = []
        while (len(players_received) < pack.player_count):
            available_rarities = [r for r in pack.rarity_odds.keys() if ((pack.rarity_odds[r] > 0) and players_by_rarity.get(r, []))]
            if (not available_rarities):
                break  # لا يوجد المزيد من اللاعبين
            # اختيار ندرة عشوائية
            weights = [pack.rarity_odds[r] for r in available_rarities]
            rarity = random.choices(population=available_rarities, weights=weights, k=1)[0]
            # اختيار لاعب عشوائي من الندرة المحددة مع شرط عدم التكرار
            possible_players = [p for p in players_by_rarity[rarity] if (p.id not in selected_players)]
            if (not possible_players):
                continue  # إذا لم يتبق لاعب غير مكرر، نعيد المحاولة
            player = random.choice(possible_players)
            selected_players.add(player.id)  # إضافة اللاعب إلى القائمة لمنع التكرار
            # جلب معلومات النادي
            club_detail = (ClubDetail.query.get(player.club_id) or ClubDetail.query.first())
            club_name = (club_detail.club_name if club_detail else "نادي افتراضي")
            # إنشاء كائن لاعب للمستخدم
            user_player = UserPlayer(user_id=current_user.id, player_id=player.id, player_position=player.position, sale_code=generate_random_code(), acquired_at=datetime.utcnow())
            db.session.add(user_player)
            # إضافة بيانات اللاعب إلى الرد
            players_received.append({'id': player.id, 'name': player.name, 'rating': player.rating, 'position': player.position, 'image_url': player.image_url, 'rarity': player.rarity, 'nationality': player.nationality, 'club_name': club_name})
        # إذا لم يتم استلام أي لاعبين بسبب أخطاء
        if (not players_received):
            db.session.rollback()
            return jsonify({'status': 'error', 'message': 'حدثت مشكلة في إضافة اللاعبين. يرجى المحاولة مرة أخرى.'}), 500
        # تسجيل عملية شراء الباكج
        pack_purchase = PackPurchase(user_id=current_user.id, pack_id=pack.id, price_paid=pack.price, players_received=[{'player_id': p['id'], 'rarity': p['rarity']} for p in players_received])
        db.session.add(pack_purchase)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'تم فتح الباكج بنجاح', 'pack_name': pack.name, 'players_received': players_received, 'coins_remaining': current_user.coins}), 200
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
    if (request.method == 'OPTIONS'):
        return ('', 200)
    return jsonify({'status': 'success', 'csrf_token': generate_csrf()})

#=====================   الانديه    =============================================
#=====================   الانديه    =============================================

# 📌 قاعدة URL للصور
@app.route('/api_clubs', methods=['GET'])
def api_clubs():
    try:
        # استرجاع جميع الأندية من قاعدة البيانات
        clubs = ClubDetail.query.all()
        # تحويل الأندية إلى قائمة من القواميس (dictionaries)
        club_list = []
        for club in clubs:
            club_list.append({'club_id': club.club_id, 'club_name': club.club_name, 'founded_year': club.founded_year, 'coach_name': club.coach_name, 'club_image_url': (f"{BASE_URL_LOGO}{club.club_image_url}" if club.club_image_url else None), 'banner_image_url': (f"{BASE_URL_BANNER}{club.banner_image_url}" if club.banner_image_url else None), 'club_color': club.club_color, 'num_players': club.num_players})
        # إرجاع الأندية على شكل JSON
        response = jsonify({'status': 'success', 'clubs': club_list})
        return (response, 200)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

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
        if (not user_players):
            return jsonify({"status": "error", "message": "لم يتم العثور على لاعبين لهذا المستخدم"}), 404
        # ✅ تجهيز بيانات اللاعبين لإرسالها كـ JSON
        players_list = []
        for user_player in user_players:
            player = user_player.player  # جلب بيانات اللاعب من الجدول Player
            club = player.club  # جلب بيانات النادي
            players_list.append({"user_player_id": user_player.id, "player_id": player.id, "name": player.name, "rating": player.rating, "position": player.position, "image_url": (f"http:#127.0.0.1:5000/static/uploads/image_player/{player.image_url}" if player.image_url else None), "rarity": player.rarity, "rarity_arabic": get_rarity_label(player.rarity), "nationality": player.nationality, "club_name": (club.club_name if club else "نادي غير معروف"), "club_logo": (f"http:#127.0.0.1:5000/static/uploads/club_logo/{club.club_image_url}" if (club and club.club_image_url) else None), "acquired_at": user_player.acquired_at.strftime("%Y-%m-%d %H:%M:%S"), "is_listed": user_player.is_listed, "price": user_player.price})
        return jsonify({"status": "success", "players": players_list}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": f"حدث خطأ أثناء جلب اللاعبين: {str(e)}"}), 500

# ✅ دالة ترجمة الندرة إلى العربية
def get_rarity_label(rarity):
    translations = {"common": "عادي", "rare": "نادر", "epic": "أسطوري", "legendary": "خارق"}
    return translations.get(rarity, "غير معروف")

@app.route('/api/generate_players', methods=['POST'])
@jwt_required()  # ✅ تأمين الوصول باستخدام JWT
def generate_daily_players():
    try:
        user_id = get_jwt_identity()  # الحصول على معرف المستخدم من التوكن
        current_user = User.query.get(user_id)
        if (not current_user):
            return jsonify({'status': 'error', 'message': 'المستخدم غير موجود'}), 401
        # ✅ تأكد من أن الطلب يحتوي على JSON، وإذا لم يحتوي استخدم القيم الافتراضية
        request_data = (request.get_json(silent=True) or {})
        rarity = request_data.get("rarity", "common")  # الفئة المطلوبة، الافتراضي "common"
        num_players = 3  # ✅ تحديد عدد اللاعبين المستخرجين بـ 3 فقط
        # ✅ التحقق مما إذا كان المستخدم قد حصل على لاعبين بالفعل اليوم
        last_generated = GeneratedPlayer.query.filter_by(user_id=user_id, rarity=rarity).order_by(GeneratedPlayer.generated_at.desc()).first()
        if (last_generated and (last_generated.generated_at.date() == datetime.utcnow().date())):
            return jsonify({'status': 'error', 'message': 'لقد حصلت بالفعل على اللاعبين اليوم، حاول مرة أخرى غدًا'}), 400
        # ✅ جلب اللاعبين من الفئة المطلوبة عشوائيًا
        available_players = Player.query.filter_by(rarity=rarity).all()
        if (not available_players):
            return jsonify({'status': 'error', 'message': 'لا يوجد لاعبين متاحين من هذه الفئة'}), 404
        selected_players = random.sample(available_players, min(num_players, len(available_players)))
        # ✅ تخزين وقت التوليد في جدول GeneratedPlayer
        new_entry = GeneratedPlayer(user_id=user_id, rarity=rarity, generated_at=datetime.utcnow())
        db.session.add(new_entry)
        # ✅ إضافة اللاعبين إلى جدول UserPlayer
        players_data = []
        for player in selected_players:
            user_player = UserPlayer(user_id=user_id, player_id=player.id, position=player.position, is_listed=False, price=0, sale_code=generate_random_code())  # ✅ تأكد من أن هذه الدالة معرفة في مكان آخر
            db.session.add(user_player)
            players_data.append({"id": player.id, "name": player.name, "rating": player.rating, "position": player.position, "image_url": (f"http:#127.0.0.1:5000/static/uploads/image_player/{player.image_url}" if player.image_url else None), "rarity": player.rarity, "nationality": player.nationality, "club_name": (player.club.club_name if player.club else "Unknown Club")})
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
        if (not player_id):
            return jsonify({"status": "error", "message": "يجب تحديد معرف اللاعب"}), 400
        # ✅ التأكد أن اللاعب موجود في `UserPlayer`
        user_player = UserPlayer.query.filter_by(user_id=user_id, player_id=player_id).first()
        if (not user_player):
            return jsonify({"status": "error", "message": "هذا اللاعب غير مملوك للمستخدم"}), 403
        # ✅ جلب النادي الخاص باللاعب
        player = Player.query.get(player_id)
        if ((not player) or (not player.club_id)):
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
        if (not user_club_players):
            return jsonify({"status": "error", "message": "لم يتم العثور على لاعبين في الكتالوج لهذا المستخدم"}), 404
        # ✅ تجهيز بيانات اللاعبين مع بيانات الأندية
        clubs_dict = {}
        for entry in user_club_players:
            player = Player.query.get(entry.player_id)
            club = ClubDetail.query.get(entry.club_id)
            if (not player or (not club)):
                continue
            club_data = {"club_id": club.club_id, "club_name": club.club_name, "club_logo": (f"http:#127.0.0.1:5000/static/uploads/club_logo/{club.club_image_url}" if club.club_image_url else None), "players": []}
            player_data = {"player_id": player.id, "name": player.name, "rating": player.rating, "position": player.position, "image_url": (f"http:#127.0.0.1:5000/static/uploads/image_player/{player.image_url}" if player.image_url else None), "rarity": player.rarity, "rarity_arabic": get_rarity_label(player.rarity), "nationality": player.nationality}
            # ✅ تصنيف اللاعبين حسب أنديتهم
            if (club.club_id not in clubs_dict):
                clubs_dict[club.club_id] = club_data
            clubs_dict[club.club_id]["players"].append(player_data)
        return jsonify({"status": "success", "clubs": list(clubs_dict.values())}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": f"حدث خطأ أثناء جلب اللاعبين المضافين إلى الكتالوج: {str(e)}"}), 500

@app.route('/api/release_player', methods=['POST'])
@jwt_required()  # ✅ تأمين الوصول باستخدام JWT
def release_player():
    try:
        # ✅ استخراج هوية المستخدم من التوكن
        user_id = get_jwt_identity()
        data = request.get_json()
        player_id = data.get('player_id')
        if (not player_id):
            return jsonify({"status": "error", "message": "يجب تحديد معرف اللاعب"}), 400
        # ✅ التأكد أن اللاعب مملوك لهذا المستخدم
        user_player = UserPlayer.query.filter_by(user_id=user_id, player_id=player_id).first()
        if (not user_player):
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
        if (not user):
            return jsonify({"status": "error", "message": "المستخدم غير موجود"}), 404
        # ✅ إرسال عدد العملات الحالية للمستخدم
        return jsonify({"status": "success", "coins": user.coins}), 200  # ✅ تأكد من أن جدول المستخدم يحتوي على `coins`
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
        if (min_price is not None):
            query = query.filter(AdminMarketListing.price >= min_price)
        if (max_price is not None):
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
            club = (Player.query.get(player.club_id) if player else None)
            listings_data.append({"listing_id": listing.id, "price": listing.price, "status": listing.status, "listed_at": (listing.listed_at.strftime("%Y-%m-%d %H:%M:%S") if listing.listed_at else None), "expires_at": (listing.expires_at.strftime("%Y-%m-%d %H:%M:%S") if listing.expires_at else None), "admin_id": listing.admin_id, "player": {"player_id": (player.id if player else None), "name": (player.name if player else "غير معروف"), "rating": (player.rating if player else None), "position": (player.position if player else "غير محدد"), "image_url": (f"http:#127.0.0.1:5000/static/uploads/image_player/{player.image_url}" if (player and player.image_url) else None), "rarity": (player.rarity if player else "غير معروف"), "nationality": (player.nationality if player else "غير معروف"), "club_name": (club.club_name if club else "نادي غير معروف"), "club_logo": (f"http:#127.0.0.1:5000/static/uploads/club_logo/{club.club_image_url}" if (club and club.club_image_url) else None)}})
        return jsonify({"status": "success", "listings": listings_data}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": f"حدث خطأ أثناء جلب البيانات: {str(e)}"}), 500



@app.route('/delete_subscription_pruchases', methods=['POST'])
@login_required
@permission_required('can_manage_subscriptions')
@csrf.exempt
def delete_subscription_pruchases():
    try:
        data = request.get_json()
        subscription_id = data.get('subscription_id')
        user_id = data.get('user_id')

        if not subscription_id or not user_id:
            return jsonify({
                'success': False,
                'message': 'معرف الاشتراك والمستخدم مطلوبان'
            }), 400

        # Get the subscription purchase
        subscription = UserSubscriptionPurchase.query.get(subscription_id)
        if not subscription:
            return jsonify({
                'success': False,
                'message': 'الاشتراك غير موجود'
            }), 404

        # Get the user
        user = User.query.get(user_id)
        if not user:
            return jsonify({
                'success': False,
                'message': 'المستخدم غير موجود'
            }), 404

        # Reset user's subscription status and badges
        user.type_subscription = ''
        user.subscription = False
        user.has_vip_badge = False
        user.has_vip_badge_plus = False
        user.has_vip_badge_elite = False

        # Delete the subscription
        db.session.delete(subscription)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'تم حذف الاشتراك بنجاح'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in delete_subscription: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'حدث خطأ: {str(e)}'
        }), 500





# إعداد API Endpoint لإرجاع بيانات جميع الاشتراكات
@app.route('/api/subscriptions', methods=['GET'])
def get_subscriptions():
    subscriptions = Subscription.query.all()  # الحصول على جميع الاشتراكات من قاعدة البيانات
    result = []
    for subscription in subscriptions:
        # تحويل كل اشتراك إلى dict داخل الـ route مباشرة
        result.append({'id': subscription.id, 'package_type': subscription.package_type, 'package_details': subscription.package_details, 'price': subscription.price, 'is_outside_egypt': subscription.is_outside_egypt, 'created_at': subscription.created_at.isoformat()})  # تنسيق تاريخ الإنشاء ليكون بصيغة ISO
    return jsonify(result)




# دالة للتحقق من الاشتراكات المنتهية وحذفها or تعطيلها
def check_expired_subscriptions():
    try:
        current_time = datetime.utcnow()
        expired_subscriptions = UserSubscriptionPurchase.query.filter(UserSubscriptionPurchase.expiry_date <= current_time, UserSubscriptionPurchase.status == 'active').all()
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
            last_daily = GeneratedPlayer.query.filter_by(user_id=current_user.id).order_by(GeneratedPlayer.generated_at.desc()).first()
            if last_daily:
                time_since_last = (datetime.utcnow() - last_daily.generated_at)
                if (time_since_last < timedelta(days=1)):
                    can_open_daily = False
                    time_remaining = (timedelta(days=1) - time_since_last)
                    daily_pack_end_timestamp = (datetime.utcnow() + time_remaining).timestamp()
                else:
                    can_open_daily = True
            else:
                can_open_daily = True
            # التحقق من حالة الاشتراك
            active_subscription = UserSubscriptionPurchase.query.filter_by(user_id=current_user.id, status='active').first()
            is_subscribed = bool(active_subscription)
    except Exception as e:
        app.logger.error(f"Error in home route: {str(e)}")
        return jsonify({'status': 'error', 'message': 'حدث خطأ أثناء تحميل الصفحة'}), 500
    return render_template('site/index.html',
                             user={'is_authenticated': is_authenticated, 'coins': user_coins, 'is_subscribed': is_subscribed}, available_packs=available_packs, can_open_daily=can_open_daily, daily_pack_end_timestamp=daily_pack_end_timestamp, subscription=subscription)

@app.route('/profile')
@login_required
def profile():
        # Initialize default values
        catalog_count = 0
        owned_count = 0
        user_rank = 1
        nearby_users = []
        
        # Get user statistics with safe handling
        try:
            catalog_count = UserClub.query.filter_by(user_id=current_user.id).count() or 0
            owned_count = UserPlayer.query.filter_by(user_id=current_user.id).count() or 0
        except Exception as e:
            app.logger.error(f"Error getting user statistics: {e}")

        # Calculate user ranking safely
        try:
            # Get all users and their catalog counts
            user_catalogs = {}
            all_users = User.query.all()
            
            for user in all_users:
                count = UserClub.query.filter_by(user_id=user.id).count()
                user_catalogs[user.id] = count if count is not None else 0
            
            # Sort users by catalog count
            sorted_users = sorted(user_catalogs.items(), key=lambda x: x[1], reverse=True)
            
            # Find current user's rank
            for i, (uid, _) in enumerate(sorted_users):
                if uid == current_user.id:
                    user_rank = i + 1
                    break
            
            # Get nearby users (2 above and 2 below)
            user_position = user_rank - 1
            start_idx = max(0, user_position - 2)
            end_idx = min(len(sorted_users), user_position + 3)
            
            nearby_users = []
            for idx in range(start_idx, end_idx):
                if idx < len(sorted_users):
                    user_id = sorted_users[idx][0]
                    user = User.query.get(user_id)
                    if user:
                        nearby_users.append({
                            'id': user.id,
                            'username': user.username,
                            'catalog_count': user_catalogs[user.id]
                        })
                        
        except Exception as e:
            app.logger.error(f"Error calculating rankings: {e}")

        # Get payment methods and wallet options safely
        try:
            payment_methods = PaymentMethod.query.filter_by(is_active=True).all() or []
            wallet_options = WalletRechargeOption.query.filter_by(is_active=True).all() or []
        except Exception as e:
            app.logger.error(f"Error getting payment info: {e}")
            payment_methods = []
            wallet_options = []

        # التحقق من وجود المستخدم في جدول المستفيدين
        beneficiary_info = Beneficiary.query.filter_by(email=current_user.email).first()

        return render_template('site/profile.html',
                             user=current_user,
                             catalog_count=catalog_count,
                             owned_count=owned_count,
                             user_rank=user_rank,
                             nearby_users=nearby_users,
                             payment_methods=payment_methods,
                             wallet_options=wallet_options,
                             beneficiary_info=beneficiary_info)
                             


# إضافة route للتعامل مع طلبات شحن المحفظة
@app.route('/recharge-wallet', methods=['POST'])
@csrf.exempt
@login_required
def recharge_wallet():
    try:
        data = request.get_json()
        amount = data.get('amount')
        payment_method = data.get('payment_method')
        # هنا يمكن إضافة المنطق الخاص بمعالجة الدفع
        # مثل التواصل مع بوابة الدفع الإلكتروني
        return jsonify({'status': 'success', 'message': 'تم إرسال طلب الشحن بنجاح'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

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
        ).select_from(UserPlayer).join(
            Player, UserPlayer.player_id == Player.id
        ).outerjoin(  # Change to outer join to handle cases where club might be None
            ClubDetail, Player.club_id == ClubDetail.club_id
        ).filter(UserPlayer.user_id == current_user.id).all()

        # حساب الأسعار المقترحة حسب الندرة
        price_ranges = {
            'common': (20, 50),
            'rare': (51, 100),
            'epic': (101, 150),
            'legendary': (151, 200)
        }
        players_data = []
        
        for user_player, name, rating, position, image_url, rarity, nationality, club_name, club_logo in user_players:
            min_price, max_price = price_ranges.get(rarity, (20, 50))
            suggested_price = int(rating * (max_price / 100))
            players_data.append({
                'id': user_player.id,
                'player_id': user_player.player_id,
                'name': name or "Unknown Player",
                'rating': rating or 0,
                'position': position or "Unknown",
                'image_url': image_url or 'default_player.png',
                'rarity': rarity or "common",
                'nationality': nationality or "Unknown",
                'club_name': club_name or "Unknown Club",
                'club_logo': club_logo or 'default_club.png',
                'suggested_price': suggested_price,
                'sale_code': user_player.sale_code
            })
        
        return render_template('site/myplayers.html', players=players_data, user=current_user)
    except Exception as e:
        app.logger.error(f"Error in myplayers route: {str(e)}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'حدث خطأ أثناء تحميل الصفحة'}), 500

@app.route('/collect_player', methods=['POST'])
@login_required
def collect_player():
    try:
        data = request.get_json()
        if (not data or (not data.get('playerData'))):
            return jsonify({'status': 'error', 'message': 'بيانات غير صحيحة'}), 400
        player_data = data['playerData']
        player_id = player_data.get('id')
        user_player_id = player_data.get('user_player_id')
        if (not player_id or (not user_player_id)):
            return jsonify({'status': 'error', 'message': 'معرف اللاعب غير موجود'}), 400
        # التحقق من وجود اللاعب في قاعدة البيانات
        player = Player.query.get(player_id)
        if (not player):
            return jsonify({'status': 'error', 'message': 'اللاعب غير موجود'}), 404
        # التحقق من وجود اللاعب في الكتالوج
        existing_in_catalog = UserClub.query.filter_by(user_id=current_user.id, player_id=player_id).first()
        if existing_in_catalog:
            return jsonify({'status': 'warning', 'message': 'هذا اللاعب موجود بالفعل في الكتالوج'}), 409
        # التحقق من أن المستخدم يمتلك اللاعب
        user_player = UserPlayer.query.filter_by(id=user_player_id, user_id=current_user.id, player_id=player_id).first()
        if (not user_player):
            return jsonify({'status': 'error', 'message': 'أنت لا تمتلك هذا اللاعب'}), 403
        # إضافة اللاعب إلى كتالوج المستخدم
        try:
            user_club = UserClub(user_id=current_user.id, player_id=player_id, club_id=player.club_id)
            db.session.add(user_club)
            db.session.delete(user_player)
            db.session.commit()
            return jsonify({'status': 'success', 'message': 'تم إضافة اللاعب للكتالوج بنجاح', 'player_id': player_id}), 200
        except Exception as e:
            db.session.rollback()
            raise e
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in collect_player: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/sell_player', methods=['POST'])
@login_required
def sell_player():
    try:
        data = request.get_json()
        if (not data):
            return jsonify({'status': 'error', 'message': 'بيانات غير صحيحة'}), 400
        player_id = data.get('player_id')
        user_player_id = data.get('user_player_id')
        price = data.get('price', 0)
        if (not player_id or (not user_player_id)):
            return jsonify({'status': 'error', 'message': 'معرف اللاعب غير موجود'}), 400
        # التحقق من وجود اللاعب وملكية المستخدم له
        user_player = UserPlayer.query.filter_by(id=user_player_id, user_id=current_user.id, player_id=player_id).first()
        if (not user_player):
            return jsonify({'status': 'error', 'message': 'اللاعب غير موجود أو غير مملوك لك'}), 404
        # إضافة العملات للمستخدم
        current_user.coins += price
        # حذف اللاعب
        db.session.delete(user_player)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'تم بيع اللاعب بنجاح وإضافة العملات لحسابك', 'new_balance': current_user.coins, 'player_id': player_id}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in sell_player: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/open_package/<int:pack_id>', methods=['POST', 'OPTIONS'])
@csrf.exempt
@login_required
def open_package(pack_id):
    if (request.method == 'OPTIONS'):
        return ('', 200)
    try:
        # التحقق من تسجيل الدخول
        if (not current_user.is_authenticated):
            return jsonify({'status': 'error', 'message': 'يجب تسجيل الدخول للوصول إلى هذه الصفحة'}), 401
        # التحقق من الباكج
        pack = Pack.query.get_or_404(pack_id)
        if (not pack.is_active):
            return jsonify({'status': 'error', 'message': 'هذا الباكج غير متاح حالياً'}), 400
        if (current_user.coins < pack.price):
            return jsonify({'status': 'error', 'message': 'ليس لديك عملات كافية لفتح هذا الباكج'}), 400
        # جلب جميع اللاعبين المتاحين
        all_players = Player.query.all()
        if (not all_players):
            return jsonify({'status': 'error', 'message': 'لا يوجد لاعبين في النظام. يرجى المحاولة لاحقاً.'}), 404
        # خصم العملات
        current_user.coins -= pack.price
        # تصنيف اللاعبين حسب الندرة
        players_by_rarity = {'common': [p for p in all_players if (p.rarity == 'common')], 'rare': [p for p in all_players if (p.rarity == 'rare')], 'epic': [p for p in all_players if (p.rarity == 'epic')], 'legendary': [p for p in all_players if (p.rarity == 'legendary')]}
        # التحقق من توفر اللاعبين لكل ندرة
        missing_rarities = [r for (r, c) in pack.rarity_odds.items() if ((c > 0) and (not players_by_rarity.get(r, [])))]
        if missing_rarities:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': f'لا يوجد لاعبين من الفئات التالية: {", ".join(missing_rarities)}. يرجى المحاولة لاحقاً.'}), 404
        # اختيار اللاعبين
        selected_players = set()
        players_received = []
        while (len(players_received) < pack.player_count):
            available_rarities = [r for r in pack.rarity_odds.keys() if ((pack.rarity_odds[r] > 0) and players_by_rarity.get(r, []))]
            if (not available_rarities):
                break
            weights = [pack.rarity_odds[r] for r in available_rarities]
            rarity = random.choices(population=available_rarities, weights=weights, k=1)[0]
            possible_players = [p for p in players_by_rarity[rarity] if (p.id not in selected_players)]
            if (not possible_players):
                continue
            player = random.choice(possible_players)
            selected_players.add(player.id)
            club_detail = (ClubDetail.query.get(player.club_id) or ClubDetail.query.first())
            club_name = (club_detail.club_name if club_detail else "نادي افتراضي")
            user_player = UserPlayer(user_id=current_user.id, player_id=player.id, position=player.position, sale_code=generate_random_code(), acquired_at=datetime.utcnow())
            db.session.add(user_player)
            players_received.append({'id': player.id, 'name': player.name, 'rating': player.rating, 'position': player.position, 'image_url': player.image_url, 'rarity': player.rarity, 'nationality': player.nationality, 'club_name': club_name})
        if (not players_received):
            db.session.rollback()
            return jsonify({'status': 'error', 'message': 'حدثت مشكلة في إضافة اللاعبين. يرجى المحاولة مرة أخرى.'}), 500
        # تسجيل عملية شراء الباكج
        pack_purchase = PackPurchase(user_id=current_user.id, pack_id=pack.id, price_paid=pack.price, players_received=[{'player_id': p['id'], 'rarity': p['rarity']} for p in players_received])
        db.session.add(pack_purchase)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'تم فتح الباكج بنجاح', 'pack_name': pack.name, 'players_received': players_received, 'coins_remaining': current_user.coins}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error opening package: {str(e)}")
        return jsonify({'status': 'error', 'message': f'حدث خطأ أثناء فتح الباكج: {str(e)}'}), 500




@app.route('/generate_daily_pack', methods=['POST'])
@login_required
@csrf.exempt
def generate_daily_pack():
    try:
        # Get user's subscription status for daily pack count
        subscription = UserSubscriptionPurchase.query.filter(
            UserSubscriptionPurchase.user_id == current_user.id,
            UserSubscriptionPurchase.status == 'active'
        ).first()

        # Debugging: Log subscription details
        if subscription:
            app.logger.info(f"Subscription Found: {subscription}")
            if hasattr(subscription, 'subscription') and subscription.subscription:
                app.logger.info(f"Subscription Plan: {subscription.subscription}")
                app.logger.info(f"Daily Free Packs from DB: {subscription.subscription.daily_free_packs}")
            else:
                app.logger.warning(f"Subscription exists but has no valid subscription plan!")
        else:
            app.logger.warning(f"No active subscription found for user {current_user.id}")

        # Calculate daily packs based on subscription
        daily_packs = 1  # Default for free users
        if subscription and hasattr(subscription, 'subscription') and subscription.subscription:
            daily_packs = max(1, subscription.subscription.daily_free_packs or 1)
        
        # Debugging: Log calculated daily packs
        app.logger.info(f"Daily Packs (After Fix): {daily_packs}")

        # Calculate time between packs correctly
        hours_between_packs = max(1, 24 / daily_packs)
        
        # Debugging: Log calculated time interval
        app.logger.info(f"Hours Between Packs: {hours_between_packs}")

        # Check last generation time
        last_generated = GeneratedPlayer.query.filter_by(
            user_id=current_user.id
        ).order_by(GeneratedPlayer.generated_at.desc()).first()

        if last_generated:
            next_available = last_generated.generated_at + timedelta(hours=hours_between_packs)
            if datetime.utcnow() < next_available:
                time_remaining = next_available - datetime.utcnow()
                return jsonify({
                    'status': 'error',
                    'message': f'الباكج متاح بعد {time_remaining.seconds // 3600} ساعة و {(time_remaining.seconds % 3600) // 60} دقيقة'
                }), 400

        # Select random common players
        available_players = Player.query.filter_by(rarity='common').all()
        if not available_players:
            return jsonify({
                'status': 'error',
                'message': 'لا يوجد لاعبين متاحين'
            }), 404

        # Select players and create records atomically
        players_data = []
        try:
            # Create generation record
            new_generation = GeneratedPlayer(
                user_id=current_user.id,
                rarity='common',
                generated_at=datetime.utcnow()
            )
            db.session.add(new_generation)

            # Select and add players
            selected_players = random.sample(available_players, min(3, len(available_players)))
            for player in selected_players:
                # Create user player record
                user_player = UserPlayer(
                    user_id=current_user.id,
                    player_id=player.id,
                    position=player.position,
                    is_listed=False,
                    price=0,
                    sale_code=generate_random_code(),
                    acquired_at=datetime.utcnow()
                )
                db.session.add(user_player)
                
                # Get club info
                club = ClubDetail.query.get(player.club_id) if player.club_id else None
                
                # Add to response data with proper image URL
                image_url = None
                if player.image_url:
                    image_url = url_for('static', 
                                      filename=f'uploads/image_player/{player.image_url}',
                                      _external=True)
                
                players_data.append({
                    "id": player.id,
                    "name": player.name,
                    "rating": player.rating,
                    "position": player.position,
                    "image_url": image_url,
                    "rarity": player.rarity,
                    "nationality": player.nationality,
                    "club_name": club.club_name if club else "Unknown Club",
                    "sale_code": user_player.sale_code
                })

            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'message': 'تم فتح الباكج اليومي بنجاح',
                'players': players_data,
                'next_available': (datetime.utcnow() + timedelta(hours=hours_between_packs)).isoformat()
            })

        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error in generate_daily_pack: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'حدث خطأ في قاعدة البيانات'
            }), 500

    except Exception as e:
        app.logger.error(f"Error in generate_daily_pack: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500



@app.route('/market')
@login_required
def market():
    try:
        # Query active market listings and join player and club details
        listings_query = AdminMarketListing.query.filter(AdminMarketListing.status == 'active').all()
        listings = []
        for listing in listings_query:
            player = listing.player
            club = (player.club if player else None)
            listings.append({'listing_id': listing.id, 'price': listing.price, 'listed_at': (listing.listed_at.strftime("%Y-%m-%d %H:%M:%S") if listing.listed_at else ""), 'expires_at': (listing.expires_at.strftime("%Y-%m-%d %H:%M:%S") if listing.expires_at else ""), 'player': {'id': player.id, 'name': player.name, 'rating': player.rating, 'position': player.position, 'image_url': player.image_url, 'rarity': player.rarity, 'nationality': player.nationality}, 'club': {'club_name': (club.club_name if club else ""), 'club_image_url': (club.club_image_url if club else "")}})
        return render_template('site/market.html', listings=listings, user={'is_authenticated': True, 'coins': current_user.coins}, username=current_user.username)
    except Exception as e:
        app.logger.error(f"Error in market route: {str(e)}")
        flash('حدث خطأ أثناء تحميل صفحة السوق', 'error')
        return redirect(url_for('index'))

@app.route('/update_profile', methods=['POST'])
@login_required
@csrf.exempt
def update_profile():
    try:
        data = request.get_json()
        field = data.get('field')
        value = data.get('value')
        if (not field or (value is None)):
            return jsonify({'status': 'error', 'message': 'معلومات غير كاملة'}), 400
        # التحقق من الحقول المسموح تحديثها
        allowed_fields = ['username', 'email', 'phone', 'country', 'state', 'city']
        if (field not in allowed_fields):
            return jsonify({'status': 'error', 'message': 'حقل غير مسموح به'}), 400
        # التحقق من تفرد اسم المستخدم والبريد الإلكتروني
        if (field in ['username', 'email', 'phone']):
            existing_user = User.query.filter(getattr(User, field) == value, User.id != current_user.id).first()
            if existing_user:
                return jsonify({'status': 'error', 'message': f'هذا {field} مستخدم بالفعل'}), 400
        # تحديث الحقل
        setattr(current_user, field, value)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'تم تحديث المعلومات بنجاح', 'value': value})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/collect_team_collector_reward', methods=['POST'])
@login_required
@csrf.exempt
def collect_team_collector_reward():
    try:
        if (not current_user.has_full_team):
            return jsonify({'status': 'error', 'message': 'لم تجمع فريق كامل بعد'}), 400
        if current_user.team_collector_reward_collected:
            return jsonify({'status': 'error', 'message': 'تم تحصيل هذه المكافأة مسبقاً'}), 400
        # إضافة العملات للمستخدم
        current_user.coins += 100
        # تحديث حالة تحصيل المكافأة
        current_user.team_collector_reward_collected = True
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'تم تحصيل 100 عملة بنجاح!', 'new_balance': current_user.coins})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/collect_rare_expert_reward', methods=['POST'])
@login_required
@csrf.exempt
def collect_rare_expert_reward():
    try:
        if (not current_user.has_rare_experts):
            return jsonify({'status': 'error', 'message': 'لم تجمع 10 لاعبين خارقين بعد'}), 400
        if current_user.rare_expert_reward_collected:
            return jsonify({'status': 'error', 'message': 'تم تحصيل هذه المكافأة مسبقاً'}), 400
        # إضافة العملات للمستخدم
        current_user.coins += 150
        # تحديث حالة تحصيل المكافأة
        current_user.rare_expert_reward_collected = True
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'تم تحصيل 150 عملة بنجاح!', 'new_balance': current_user.coins})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/collect_catalog_king_reward', methods=['POST'])
@login_required
@csrf.exempt
def collect_catalog_king_reward():
    try:
        if (not current_user.has_four_catalogs):
            return jsonify({'status': 'error', 'message': 'لم تكمل 4 كتالوجات بعد'}), 400
        if current_user.catalog_king_reward_collected:
            return jsonify({'status': 'error', 'message': 'تم تحصيل هذه المكافأة مسبقاً'}), 400
        # إضافة العملات للمستخدم
        current_user.coins += 200
        # تحديث حالة تحصيل المكافأة
        current_user.catalog_king_reward_collected = True
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'تم تحصيل 200 عملة بنجاح!', 'new_balance': current_user.coins})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500




@app.route('/add_promotion', methods=['GET', 'POST'])
@login_required
@permission_required('can_manage_promotions')
def add_promotion():
    form = PromotionForm()
    if form.validate_on_submit():
        try:
            image_url = None
            if form.image.data:
                filename = secure_filename(form.image.data.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER_PROMOTIONS'], filename)
                form.image.data.save(filepath)
                image_url = filename

            promotion = Promotion(
                name=form.name.data,
                description=form.description.data,
                image_url=image_url,
                original_price=form.original_price.data,
                discount_percentage=form.discount_percentage.data,
                final_price=form.final_price.data,
                promotion_type=form.promotion_type.data,
                coins_reward=form.coins_reward.data,
                free_packs=form.free_packs.data,
                vip_duration_days=form.vip_duration_days.data,
                end_date=form.end_date.data,
                features=[]  # يمكن إضافة المميزات لاحقاً
            )
            
            db.session.add(promotion)
            db.session.commit()
            flash('تم إضافة العرض بنجاح!', 'success')
            return redirect(url_for('promotions'))
        except Exception as e:
            db.session.rollback()
            flash(f'حدث خطأ: {str(e)}', 'error')
    
    return render_template('add_promotion.html', form=form)

@app.route('/promotions')
def promotions():
    active_promotions = Promotion.query.filter_by(is_active=True).all()
    return render_template('site/promotions.html', 
                         promotions=active_promotions,
                         user=current_user)

@app.route('/api/promotions', methods=['GET'])
def get_promotions():
    promotions = Promotion.query.filter_by(is_active=True).all()
    return jsonify([{
        'id': p.id,
        'name': p.name,
        'description': p.description,
        'image_url': p.image_url,
        'original_price': p.original_price,
        'discount_percentage': p.discount_percentage,
        'final_price': p.final_price,
        'features': p.features,
        'remaining_time': p.remaining_time,
        'promotion_type': p.promotion_type,
        'coins_reward': p.coins_reward,
        'free_packs': p.free_packs,
        'vip_duration_days': p.vip_duration_days
    } for p in promotions])



@app.route('/toggle_permission/<int:user_id>', methods=['POST'])
@login_required
@permission_required('can_manage_users')
@csrf.exempt  # Add CSRF exemption for API endpoint
def toggle_permission(user_id):
    try:
        if not current_user.is_admin:
            return jsonify({'success': False, 'message': 'غير مصرح لك بهذا الإجراء'}), 403

        # Ensure request has JSON content type
        if not request.is_json:
            return jsonify({'success': False, 'message': 'Content-Type must be application/json'}), 400

        data = request.get_json()
        permission = data.get('permission')
        value = data.get('value', False)

        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': 'المستخدم غير موجود'}), 404
        
        # Prevent changing own permissions
        if user.id == current_user.id:
            return jsonify({'success': False, 'message': 'لا يمكنك تغيير صلاحياتك الخاصة'}), 403

        valid_permissions = [
            'can_manage_dashboard',
            'can_manage_users',
            'can_manage_players',
            'can_manage_clubs',
            'can_manage_packs',
            'can_manage_market',
            'can_manage_subscriptions',
            'can_manage_promotions'
        ]

        if permission not in valid_permissions:
            return jsonify({'success': False, 'message': 'صلاحية غير صالحة'}), 400

        setattr(user, permission, value)
        db.session.commit()

        message = f"تم {'منح' if value else 'إلغاء'} صلاحية {permission} للمستخدم {user.username}"
        return jsonify({
            'success': True, 
            'message': message,
            'data': {
                'user_id': user.id,
                'permission': permission,
                'value': value
            }
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in toggle_permission: {str(e)}")
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء تحديث الصلاحيات'}), 500


def apply_subscription_benefits(user_id, subscription_id):
    """Apply all subscription benefits after successful purchase"""
    try:
        user = User.query.get(user_id)
        subscription = Subscription.query.get(subscription_id)
        
        if not user or not subscription:
            return False
        
        # Set VIP badges
        user.has_vip_badge = subscription.has_vip_badge
        user.has_vip_badge_plus = subscription.has_vip_badge_plus
        
        # If both VIP and VIP+ are enabled, set Elite instead
        if subscription.has_vip_badge and subscription.has_vip_badge_plus:
            user.has_vip_badge = False
            user.has_vip_badge_plus = False
            user.has_vip_badge_elite = True
            
        # Generate joker players safely
        if subscription.joker_players > 0:
            epic_players = Player.query.filter_by(rarity='legendary').all()
            
            if epic_players:
                selected_players = random.choices(epic_players, k=min(len(epic_players), subscription.joker_players))
                
                for joker_player in selected_players:
                    user_player = UserPlayer(
                        user_id=user.id,
                        player_id=joker_player.id,
                        position=joker_player.position,
                        sale_code=generate_random_code()
                    )
                    db.session.add(user_player)
        
        # Add coins reward here only
        user.coins += subscription.coins_reward
        
        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in apply_subscription_benefits: {str(e)}")
        return False

@app.route('/toggle_user_status/<int:user_id>', methods=['POST'])
@login_required
@permission_required('can_manage_users')
def toggle_user_status(user_id):
    try:
        if not current_user.is_admin:
            return jsonify({
                'success': False,
                'message': 'غير مصرح لك بهذا الإجراء'
            }), 403

        user = User.query.get_or_404(user_id)

        if user.id == current_user.id:
            return jsonify({
                'success': False,
                'message': 'لا يمكنك تغيير حالة حسابك الخاص'
            }), 403

        # تغيير حالة المستخدم
        user.is_active = not user.is_active
        
        # إذا تم تعطيل المستخدم، قم بإلغاء جميع الصلاحيات
        if not user.is_active:
            user.is_admin = False
            user.can_manage_dashboard = False
            user.can_manage_users = False
            user.can_manage_players = False
            user.can_manage_clubs = False
            user.can_manage_packs = False
            user.can_manage_market = False
            user.can_manage_subscriptions = False
            user.can_manage_promotions = False

        db.session.commit()

        message = f"تم {'تفعيل' if user.is_active else 'تعطيل'} حساب {user.username}"
        return jsonify({
            'success': True,
            'message': message,
            'is_active': user.is_active
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'حدث خطأ: {str(e)}'
        }), 500

@app.route('/delete_user/<int:user_id>', methods=['DELETE'])
@login_required
@permission_required('can_manage_users')
def delete_user(user_id):
    try:
        if not current_user.is_admin:
            return jsonify({
                'success': False,
                'message': 'غير مصرح لك بهذا الإجراء'
            }), 403

        user = User.query.get_or_404(user_id)

        if user.id == current_user.id:
            return jsonify({
                'success': False,
                'message': 'لا يمكنك حذف حسابك الخاص'
            }), 403

        # حذف القوائم في السوق المرتبطة بالمستخدم
        AdminMarketListing.query.filter_by(admin_id=user_id).delete()
        
        # حذف جميع البيانات المرتبطة بالمستخدم
        UserPlayer.query.filter_by(user_id=user_id).delete()
        UserClub.query.filter_by(user_id=user_id).delete()
        PackPurchase.query.filter_by(user_id=user_id).delete()
        UserSubscriptionPurchase.query.filter_by(user_id=user_id).delete()
        Transaction.query.filter((Transaction.buyer_id == user_id) | 
                               (Transaction.seller_id == user_id)).delete()
        GeneratedPlayer.query.filter_by(user_id=user_id).delete()

        # حذف المستخدم نفسه
        db.session.delete(user)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'تم حذف المستخدم {user.username} وجميع بياناته بنجاح'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in delete_user: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'حدث خطأ أثناء حذف المستخدم: {str(e)}'
        }), 500

@app.route('/coming-soon')
def coming_soon():
    target_date = datetime(2025, 6, 15)
    user = {
        'is_authenticated': current_user.is_authenticated,
        'coins': current_user.coins if current_user.is_authenticated else 0
    }
    return render_template('site/coming-soon.html', 
                         target_date=target_date,
                         user=user)

@app.route('/admin/payment_methods', methods=['GET', 'POST'])
@login_required
@permission_required('can_manage_dashboard')
def manage_payment_methods():
    try:
        payment_methods = PaymentMethod.query.all()
        # Initialize empty icon if None
        for method in payment_methods:
            if method.icon is None:
                method.icon = 'default-payment.png'
                
        return render_template('admin/payment_methods.html', 
                             payment_methods=payment_methods, 
                             username=current_user.username)
    except Exception as e:
        app.logger.error(f"Error in manage_payment_methods: {str(e)}")
        flash('حدث خطأ أثناء تحميل طرق الدفع', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/payment_methods', methods=['POST'])
@login_required
@permission_required('can_manage_dashboard')
def add_payment_method():
    try:
        # التحقق من نوع الطلب
        if request.content_type == 'application/json':
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        if not data:
            return jsonify({
                'success': False,
                'message': 'لم يتم استلام بيانات'
            }), 400

        # معالجة الصورة إذا وجدت
        icon = None
        if 'icon' in request.files:
            file = request.files['icon']
            if file and file.filename:
                filename = secure_filename(file.filename)
                icon_path = os.path.join(app.config['UPLOAD_FOLDER_PAYMENT_METHODS'], filename)
                file.save(icon_path)
                icon = filename

        # إنشاء كائن طريقة دفع جديد
        new_method = PaymentMethod(
            name=data.get('name'),
            description=data.get('description'),
            icon=icon,
            wallet_number=data.get('wallet_number'),
            is_egypt_only=data.get('is_egypt_only', False),
            is_active=data.get('is_active', True)
        )

         # حفظ معلومات بوابة الدفع
        if 'gateway_type' in data:
            gateway_config = {
               'type': data['gateway_type'],
                'config': data.get('gateway_config', {})
            }
            new_method.gateway_config = json.dumps(gateway_config)

        db.session.add(new_method)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'تم إضافة طريقة الدفع بنجاح',
            'method': {
                'id': new_method.id,
                'name': new_method.name,
                'icon': icon
            }
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in add_payment_method: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'حدث خطأ أثناء إضافة طريقة الدفع: {str(e)}'
        }), 500


import requests
from requests.exceptions import RequestException

def get_paymob_auth(api_key):
    """Enhanced PayMob authentication with proper token handling"""
    if not api_key or len(api_key.strip()) < 10:
        raise ValueError("Invalid PayMob API key format")
        
    try:
        # First authentication step - Get authentication token
        auth_response = requests.post(
            "https://accept.paymob.com/api/auth/tokens",
            json={"api_key": api_key.strip()},
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "StarcatcherWeb/1.0"
            },
            timeout=30,
            verify=True
        )
        
        # Handle common API errors
        if auth_response.status_code == 403:
            raise ValueError("Invalid or unauthorized PayMob API key")
        elif auth_response.status_code == 429:
            raise ValueError("Too many API requests, please try again later")
        
        auth_response.raise_for_status()
        auth_data = auth_response.json()
        
        if 'token' not in auth_data:
            raise ValueError("Invalid PayMob response: missing token")
            
        # Second step - Register order
        token = auth_data['token']
        order_data = {
            "auth_token": token,
            "delivery_needed": "false",
            "amount_cents": session.get('payment_data', {}).get('amount', 0),
            "currency": "EGP",
            "items": []
        }
        
        order_response = requests.post(
            "https://accept.paymob.com/api/ecommerce/orders",
            json=order_data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
            }
        )
        
        order_response.raise_for_status()
        order_data = order_response.json()
        
        if 'id' not in order_data:
            raise ValueError("Failed to create PayMob order")
            
        # Third step - Get payment key
        payment_key_request = {
            "auth_token": token,
            "amount_cents": session.get('payment_data', {}).get('amount', 0),
            "expiration": 3600,
            "order_id": order_data['id'],
            "billing_data": {
                "email": "test@test.com",
                "first_name": "Test",
                "last_name": "Account",
                "phone_number": "+20000000000",
                "apartment": "NA",
                "floor": "NA",
                "street": "NA",
                "building": "NA",
                "shipping_method": "NA",
                "postal_code": "NA",
                "city": "NA",
                "country": "NA",
                "state": "NA"
            },
            "currency": "EGP",
            "integration_id": session.get('payment_data', {}).get('integration_id')
        }
        
        payment_key_response = requests.post(
            "https://accept.paymob.com/api/acceptance/payment_keys",
            json=payment_key_request,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
            }
        )
        
        payment_key_response.raise_for_status()
        payment_key_data = payment_key_response.json()
        
        if 'token' not in payment_key_data:
            raise ValueError("Failed to get payment key")
            
        return payment_key_data['token']
        
    except requests.exceptions.RequestException as e:
        app.logger.error(f"PayMob API request failed: {str(e)}")
        raise Exception(f"Payment gateway connection error: {str(e)}")
        
    except ValueError as e:
        app.logger.error(f"PayMob API error: {str(e)}")
        raise
        
    except Exception as e:
        app.logger.error(f"Unexpected PayMob error: {str(e)}")
        raise Exception("Payment gateway error occurred")


@app.route('/start_payment', methods=['POST'])
@login_required
@csrf.exempt
def start_payment():
    try:
        if not request.is_json:
            return jsonify({'success': False, 'message': 'Invalid content type'}), 400

        data = request.get_json()
        if not all(k in data for k in ['amount', 'coins', 'method_id']):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400

        method = PaymentMethod.query.get(data['method_id'])
        if not method or not method.is_active:
            return jsonify({'success': False, 'message': 'Invalid or inactive payment method'}), 400

        try:
            amount_cents = int(float(data['amount']) * 100)
            api_key = method.gateway_api_key

            # Get authentication token with proper headers
            auth_response = requests.post(
                "https://accept.paymob.com/api/auth/tokens",
                json={"api_key": api_key},
                headers={
                    "Content-Type": "application/json"
                },
                timeout=30
            )

            app.logger.info(f"Auth Response: {auth_response.text}")
            auth_data = auth_response.json()
            
            # Fix token extraction - it's directly in the response
            auth_token = auth_data.get('token')
            if not auth_token:
                app.logger.error(f"No token found in response: {auth_data}")
                raise ValueError("Invalid PayMob response: no token found")

            # Rest of the payment flow...
            order_request = {
                "auth_token": auth_token,
                "delivery_needed": "false",
                "amount_cents": str(amount_cents),  # Convert to string
                "currency": "EGP",
                "merchant_order_id": str(int(time.time())),  # Add unique order ID
                "items": [],
            }

            order_response = requests.post(
                "https://accept.paymob.com/api/ecommerce/orders",
                json=order_request,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {auth_token}"
                }
            )

            if order_response.status_code != 201:
                app.logger.error(f"Order creation failed: {order_response.text}")
                raise ValueError("Order creation failed")

            order_id = order_response.json().get('id')

            # Get payment key
            billing_data = {
                "apartment": "NA",
                "email": current_user.email,
                "floor": "NA",
                "first_name": current_user.username,
                "street": "NA",
                "building": "NA",
                "phone_number": "+201111111111",
                "shipping_method": "NA",
                "postal_code": "NA",
                "city": "NA",
                "country": "EG",
                "last_name": "NA",
                "state": "NA"
            }

            payment_token_request = {
                "auth_token": auth_token,
                "amount_cents": str(amount_cents),  # Convert to string
                "expiration": 3600,
                "order_id": order_id,
                "billing_data": billing_data,
                "currency": "EGP",
                "integration_id": method.gateway_integration_id,
                "lock_order_when_paid": "false"
            }

            payment_key_response = requests.post(
                "https://accept.paymob.com/api/acceptance/payment_keys",
                json=payment_token_request,
                headers={
                    "Content-Type": "application/json"
                }
            )

            if payment_key_response.status_code != 201:
                app.logger.error(f"Payment key error: {payment_key_response.text}")
                raise ValueError("Failed to get payment key")

            payment_token = payment_key_response.json().get('token')

            if not payment_token:
                raise ValueError("No payment token received")

            # Save to session
            session['payment_data'] = {
                'order_id': order_id,
                'amount': amount_cents,
                'coins': data['coins'],
                'method_id': data['method_id']
            }

            # Return iframe URL
            return jsonify({
                'success': True,
                'redirect_url': f"https://accept.paymob.com/api/acceptance/iframes/{method.gateway_iframe_id}?payment_token={payment_token}"
            })

        except ValueError as e:
            app.logger.error(f"Payment configuration error: {str(e)}")
            return jsonify({'success': False, 'message': str(e)}), 400

        except Exception as e:
            app.logger.error(f"Payment processing error: {str(e)}")
            return jsonify({'success': False, 'message': 'Payment processing failed'}), 500

    except Exception as e:
        app.logger.error(f"Payment route error: {str(e)}")
        return jsonify({'success': False, 'message': 'Payment system error'}), 500


@app.route('/api/payment-methods', methods=['GET'])
@login_required
def get_payment_methods():
    try:
        methods = PaymentMethod.query.all()
        return jsonify({
            'success': True,
            'methods': [method.to_dict() for method in methods]
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'حدث خطأ أثناء جلب طرق الدفع: {str(e)}'
        }), 400

@app.route('/api/payment-methods/add', methods=['POST'])
@login_required
@permission_required('can_manage_dashboard')
@csrf.exempt
def add_payment_method_api():
    try:
        data = request.get_json()
        
        new_method = PaymentMethod(
            name=data.get('name'),
            description=data.get('description'),
            icon=data.get('icon'),
            wallet_number=data.get('wallet_number'),
            is_egypt_only=data.get('is_egypt_only', False),
            is_active=data.get('is_active', True),
            instructions=data.get('instructions'),
            # Add new gateway fields
            gateway_type=data.get('gateway_type'),
            gateway_api_key=data.get('gateway_api_key'),
            gateway_integration_id=data.get('gateway_integration_id'),
            gateway_iframe_id=data.get('gateway_iframe_id')
        )

        db.session.add(new_method)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'تم إضافة طريقة الدفع بنجاح',
            'method': new_method.to_dict()
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'حدث خطأ أثناء إضافة طريقة الدفع: {str(e)}'
        }), 500



@app.route('/admin/recharge-requests')
@login_required
@permission_required('can_manage_dashboard')
def recharge_requests():
        # Get all recharge requests with related user and option data
        requests = db.session.query(
            WalletRechargeRequest,
            User,
            WalletRechargeOption
        ).join(
            User,
            WalletRechargeRequest.user_id == User.id
        ).join(
            WalletRechargeOption,
            WalletRechargeRequest.option_id == WalletRechargeOption.id
        ).order_by(WalletRechargeRequest.created_at.desc()).all()

        return render_template('admin/recharge_requests.html',
                             requests=requests,
                             username=current_user.username)


@app.route('/admin/approve-recharge/<int:request_id>', methods=['POST'])
@login_required
@csrf.exempt
@permission_required('can_manage_dashboard')
def approve_recharge(request_id):
    try:
        recharge_request = WalletRechargeRequest.query.get_or_404(request_id)
        
        if recharge_request.status != 'pending':
            return jsonify({
                'success': False,
                'message': 'هذا الطلب تم معالجته مسبقاً'
            }), 400

        # Add coins to user's wallet
        user = User.query.get(recharge_request.user_id)
        user.coins += recharge_request.option.coins_amount
        
        # Update request status
        recharge_request.status = 'completed'
        recharge_request.notes = 'تم الموافقة على الطلب وإضافة العملات'
        recharge_request.updated_at = datetime.utcnow()
        
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'تم الموافقة على الطلب وإضافة العملات بنجاح',
            'new_status': 'completed',
            'new_coins': user.coins
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'حدث خطأ: {str(e)}'
        }), 500

@app.route('/admin/reject-recharge/<int:request_id>', methods=['POST'])
@login_required
@csrf.exempt
@permission_required('can_manage_dashboard')
def reject_recharge(request_id):
    try:
        data = request.get_json()
        rejection_reason = data.get('reason', 'تم رفض الطلب')
        
        recharge_request = WalletRechargeRequest.query.get_or_404(request_id)
        
        if recharge_request.status != 'pending':
            return jsonify({
                'success': False,
                'message': 'هذا الطلب تم معالجته مسبقاً'
            }), 400

        recharge_request.status = 'rejected'
        recharge_request.notes = rejection_reason
        recharge_request.updated_at = datetime.utcnow()
        
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'تم رفض الطلب بنجاح',
            'new_status': 'rejected'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'حدث خطأ: {str(e)}'
        }), 500

# Wallet Options Admin Routes
@app.route('/admin/wallet-options')
@admin_required
def admin_wallet_options():
    try:
        # Make sure the WalletRechargeOption is imported
        options = WalletRechargeOption.query.all()
        return render_template('admin/wallet_options.html', options=options)
    except Exception as e:
        # Log the error
        app.logger.error(f"Error in admin_wallet_options: {str(e)}")
        # Create table if it doesn't exist
        db.create_all()
        # Return empty options for first time
        return render_template('admin/wallet_options.html', options=[])

# Wallet Options API Routes
@app.route('/api/wallet-options', methods=['GET', 'POST'])
@admin_required
def wallet_options():
    WalletOptions = WalletRechargeOption
    if request.method == 'POST':
        data = request.get_json()
        new_option = WalletOptions(
            coins_amount=data['coins_amount'],
            price_egp=data['price_egp'],
            price_usd=data['price_usd'],
            payment_link=data['payment_link'],
            is_active=data['is_active']
        )
        db.session.add(new_option)
        db.session.commit()
        return jsonify({'message': 'تم إضافة الخيار بنجاح'}), 201
    
    options = WalletOptions.query.all()
    return jsonify([option.to_dict() for option in options])

@app.route('/api/wallet-options/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def wallet_option(id):
    WalletOptions = WalletRechargeOption
    option = WalletOptions.query.get_or_404(id)
    
    if request.method == 'GET':
        return jsonify(option.to_dict())
    
    elif request.method == 'PUT':
        data = request.get_json()
        option.coins_amount = data['coins_amount']
        option.price_egp = data['price_egp']
        option.price_usd = data['price_usd']
        option.payment_link = data['payment_link']
        option.is_active = data['is_active']
        db.session.commit()
        return jsonify({'message': 'تم تحديث الخيار بنجاح'})
    
    elif request.method == 'DELETE':
        db.session.delete(option)
        db.session.commit()
        return jsonify({'message': 'تم حذف الخيار بنجاح'})

@app.route('/beneficiaries')
@login_required
@permission_required('can_manage_dashboard')
def beneficiaries():
    try:
        beneficiaries = db.session.query(
            Beneficiary, User, func.sum(User.earned_money).label('total_earned')
        ).outerjoin(
            User, User.email == Beneficiary.email
        ).group_by(Beneficiary.id).all()

        return render_template(
            'admin/beneficiaries.html',
            beneficiaries=beneficiaries,
            username=current_user.username
        )
    except Exception as e:
        app.logger.error(f"Error in beneficiaries route: {str(e)}")
        flash('حدث خطأ أثناء تحميل صفحة المستفيدين', 'error')
        return redirect(url_for('dashboard'))

@app.route('/add_beneficiary', methods=['POST'])
@login_required
@permission_required('can_manage_users')
def add_beneficiary():
    try:
        data = request.get_json()
        email = data.get('email')
        commission_rate = float(data.get('commission_rate', 0))

        if not email or commission_rate < 0 or commission_rate > 100:
            return jsonify({
                'success': False,
                'message': 'بيانات غير صحيحة'
            }), 400

        # التحقق من وجود المستفيد
        existing = Beneficiary.query.filter_by(email=email).first()
        if existing:
            return jsonify({
                'success': False,
                'message': 'هذا البريد الإلكتروني مسجل بالفعل'
            }), 400

        new_beneficiary = Beneficiary(
            email=email,
            commission_rate=commission_rate,
            is_active=True
        )
        db.session.add(new_beneficiary)
        db.session.commit()

        # إرجاع البيانات المطلوبة للتحديث المباشر للجدول
        return jsonify({
            'success': True,
            'message': 'تمت إضافة المستفيد بنجاح',
            'beneficiary': {
                'id': new_beneficiary.id,
                'email': new_beneficiary.email,
                'commission_rate': new_beneficiary.commission_rate,
                'created_at': new_beneficiary.created_at.strftime('%Y-%m-%d'),
                'is_active': new_beneficiary.is_active,
                'total_earned': 0
            }
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding beneficiary: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'حدث خطأ أثناء إضافة المستفيد'
        }), 500

# Update subscription purchase to handle beneficiary commission
def handle_beneficiary_commission(user_email, amount):
    try:
        beneficiary = Beneficiary.query.filter_by(email=user_email).first()
        if beneficiary and beneficiary.user:
            commission = (amount * beneficiary.commission_rate) / 100
            beneficiary.user.earned_money += commission
            db.session.commit()
    except Exception as e:
        app.logger.error(f"Error handling beneficiary commission: {str(e)}")
        db.session.rollback()

@app.route('/get_beneficiary/<int:id>')
@login_required
@permission_required('can_manage_users')
def get_beneficiary(id):
    try:
        beneficiary = Beneficiary.query.get_or_404(id)
        return jsonify({
            'email': beneficiary.email,
            'commission_rate': beneficiary.commission_rate,
            'is_active': beneficiary.is_active
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@app.route('/update_beneficiary/<int:id>', methods=['POST'])
@login_required
@permission_required('can_manage_users')
def update_beneficiary(id):
    try:
        data = request.get_json()
        beneficiary = Beneficiary.query.get_or_404(id)
        
        beneficiary.commission_rate = float(data.get('commission_rate', beneficiary.commission_rate))
        beneficiary.is_active = data.get('is_active', beneficiary.is_active)
        
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'تم تحديث المستفيد بنجاح'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 400

@app.route('/delete_beneficiary/<int:id>', methods=['DELETE'])
@login_required
@permission_required('can_manage_users')
def delete_beneficiary(id):
    try:
        beneficiary = Beneficiary.query.get_or_404(id)
        db.session.delete(beneficiary)
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'تم حذف المستفيد بنجاح'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 400

@app.route('/orders')
@login_required
def orders():
        # جلب طلبات شراء الباقات
        subscription_orders = UserSubscriptionPurchase.query.filter_by(
            user_id=current_user.id
        ).order_by(UserSubscriptionPurchase.purchase_date.desc()).all()

        return render_template('site/orders.html',
                             subscription_orders=subscription_orders,
                             user=current_user)  # Pass the full user object

@app.route('/create_recharge_request', methods=['POST'])
@csrf.exempt
@login_required
def create_recharge_request():
    try:
        data = request.json
        option_id = data.get('option_id')
        amount = data.get('amount')
        payment_link = data.get('payment_link')
        currency = 'EGP' if current_user.country == 'eg' else 'USD'
        
        # Create unique transaction ID
        transaction_id = str(uuid.uuid4())
        
        # Create new recharge request
        recharge_request = WalletRechargeRequest(
            user_id=current_user.id,
            option_id=option_id,
            amount=amount,
            currency=currency,
            payment_method='online',  # You can modify this based on your needs
            payment_link=payment_link,
            transaction_id=transaction_id,
            status='pending'
        )
        
        db.session.add(recharge_request)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Recharge request created successfully',
            'redirect_url': payment_link
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/gift')
def gift():
    return render_template('site/gift.html',
                         user={'is_authenticated': current_user.is_authenticated,
                               'coins': current_user.coins if current_user.is_authenticated else 0})

