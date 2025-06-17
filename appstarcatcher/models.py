from datetime import datetime
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from appstarcatcher import db  # استيراد db من التطبيق بدلاً من تعريفه هنا
import random
import string
import json

try:
    from cryptography.fernet import Fernet
except ImportError:
    print("Warning: cryptography module not installed. Please run 'pip install cryptography'")
    # Provide fallback for encryption
    class Fernet:
        @staticmethod
        def generate_key():
            return b'dummy_key_for_development_only'
        
        def __init__(self, key):
            self.key = key
            
        def encrypt(self, data):
            return data
            
        def decrypt(self, data):
            return data

import os

# Get encryption key from environment or generate one
try:
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
    cipher_suite = Fernet(ENCRYPTION_KEY)
except Exception as e:
    print(f"Warning: Error setting up encryption: {e}")
    ENCRYPTION_KEY = b'dummy_key_for_development_only'
    cipher_suite = Fernet(ENCRYPTION_KEY)

# دالة لتوليد كود عشوائي
def generate_random_code():
    """توليد كود عشوائي مكون من 6 أحرف وأرقام"""
    characters = string.ascii_letters + string.digits  # خليط من الحروف والأرقام
    return ''.join(random.choices(characters, k=6))

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    # الحقول الجديدة
    image_url = db.Column(db.String(255), nullable=True)  # رابط الصورة
    phone = db.Column(db.String(20), unique=True, nullable=True)  # رقم الهاتف
    country = db.Column(db.String(80), nullable=True)  # الدولة
    state = db.Column(db.String(80), nullable=True)  # المحافظة
    city = db.Column(db.String(80), nullable=True)  # المدينة

    # الحقول الإضافية
    coins = db.Column(db.Integer, default=200)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    subscription = db.Column(db.Boolean, default=False)
    type_subscription = db.Column(db.String(80), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    new_member_reward_collected = db.Column(db.Boolean, default=False)
    first_purchase_reward_collected = db.Column(db.Boolean, default=False)  # عمود جديد
    team_collector_reward_collected = db.Column(db.Boolean, default=False)  # Add this new column
    rare_expert_reward_collected = db.Column(db.Boolean, default=False)
    catalog_king_reward_collected = db.Column(db.Boolean, default=False)
    earned_money = db.Column(db.Float, default=0)  # New field for earned money

    # Page permissions
    can_manage_users = db.Column(db.Boolean, default=False)
    can_manage_dashboard = db.Column(db.Boolean, default=False)
    can_manage_players = db.Column(db.Boolean, default=False)
    can_manage_clubs = db.Column(db.Boolean, default=False)
    can_manage_packs = db.Column(db.Boolean, default=False)
    can_manage_market = db.Column(db.Boolean, default=False)
    can_manage_subscriptions = db.Column(db.Boolean, default=False)
    can_manage_promotions = db.Column(db.Boolean, default=False)

    has_vip_badge = db.Column(db.Boolean, default=False)  # هل يحصل على شارة VIP في ملفه الشخصي
    has_vip_badge_plus = db.Column(db.Boolean, default=False)  # هل يحصل على شارة VIP plus في ملفه الشخصي
    has_vip_badge_elite = db.Column(db.Boolean, default=False)  # هل يحصل على شارة VIP plus في ملفه الشخصي
    
    # العلاقات
    owned_players = db.relationship('UserPlayer', backref='owner', lazy=True, foreign_keys='UserPlayer.user_id')
    pack_purchases = db.relationship('PackPurchase', backref='user', lazy=True)
    user_clubs = db.relationship('UserClub', backref='user', lazy=True)

    # Referral fields
    referral_code = db.Column(db.String(10), unique=True)
    referred_by = db.Column(db.String(10), nullable=True)
    total_referrals = db.Column(db.Integer, default=0)
    referral_earnings = db.Column(db.Integer, default=0)
    
    @staticmethod
    def generate_referral_code():
        while True:
            code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            if not User.query.filter_by(referral_code=code).first():
                return code
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if not self.referral_code:
            self.referral_code = self.generate_referral_code()

    @staticmethod
    def apply_referral_code(referral_code, new_user):
        """
        تطبيق كود الإحالة للمستخدم الجديد
        """
        if not referral_code:
            return None
            
        referrer = User.query.filter_by(referral_code=referral_code).first()
        if not referrer or referrer.id == new_user.id:
            return None
            
        # إنشاء سجل الإحالة
        referral = ReferralCode(
            referrer_id=referrer.id,
            referred_id=new_user.id,
            code_used=referral_code,
            status='completed'
        )
        
        # تحديث البيانات
        new_user.referred_by = referral_code
        referrer.total_referrals += 1
        
        # منح المكافآت
        referrer.referral_earnings += 100  # مكافأة للمحيل
        new_user.coins += 50  # مكافأة للمستخدم الجديد
        
        try:
            db.session.add(referral)
            db.session.commit()
            return referral
        except Exception as e:
            db.session.rollback()
            print(f"Error applying referral code: {e}")
            return None

    @property
    def has_bought_player(self):
        """Check if user has any completed market transactions"""
        return Transaction.query.filter_by(
            buyer_id=self.id,
            transaction_type='market',
            status='completed'
        ).first() is not None

    @property
    def has_full_team(self):
        """Check if user has collected all players from any team"""
        # Get all clubs
        clubs = ClubDetail.query.all()
        
        for club in clubs:
            # Get total players in this club
            total_players = Player.query.filter_by(club_id=club.club_id).count()
            
            # Skip if club has no players
            if (total_players == 0):
                continue
                
            # Get collected players from this club
            collected_players = UserClub.query.filter_by(
                user_id=self.id,
                club_id=club.club_id
            ).count()
            
            # If collected all players from any club, return True
            if collected_players == total_players:
                return True
        
        return False

    @property
    def has_rare_experts(self):
        """Check if user has collected 10 rare players"""
        rare_count = UserClub.query.join(Player)\
            .filter(
                UserClub.user_id == self.id,
                Player.rarity == 'legendary'
            ).count()
        return rare_count >= 10

    @property
    def has_four_catalogs(self):
        """Check if user has completed 4 club catalogs"""
        completed_clubs = 0
        clubs = ClubDetail.query.all()
        
        for club in clubs:
            total_players = Player.query.filter_by(club_id=club.club_id).count()
            if total_players == 0:
                continue
                
            collected_players = UserClub.query.filter_by(
                user_id=self.id,
                club_id=club.club_id
            ).count()
            
            if collected_players == total_players:
                completed_clubs += 1
                
        return completed_clubs >= 4

    # دالة __repr__
    def __repr__(self):
        return f"User('{self.id}', '{self.username}', '{self.email}', '{self.phone}', '{self.country}', '{self.city}', '{self.coins}', '{self.is_admin}', '{self.created_at}')"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Player(db.Model):
    __tablename__ = 'players'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    position = db.Column(db.String(50), nullable=False)
    image_url = db.Column(db.String(255))
    rarity = db.Column(db.String(50))  # common, rare, epic, legendary
    nationality = db.Column(db.String(100))
    club_id = db.Column(db.Integer, db.ForeignKey('club_details.club_id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


    # العلاقات
    club = db.relationship('ClubDetail', backref=db.backref('club_players', lazy=True))
    user_players = db.relationship('UserPlayer', backref='player', lazy=True)
    admin_listings = db.relationship('AdminMarketListing', backref='player', lazy=True)

    def __repr__(self):
        return f"Player('{self.id}', '{self.name}', '{self.rating}', '{self.position}', '{self.rarity}', '{self.nationality}')"

# جدول لتخزين آخر وقت تم فيه توليد اللاعبين لكل مستخدم
class GeneratedPlayer(db.Model):
    __tablename__ = 'generated_players'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    rarity = db.Column(db.String(50), nullable=False)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserClub(db.Model):
    __tablename__ = 'user_club'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    club_id = db.Column(db.Integer, db.ForeignKey('club_details.club_id', ondelete='CASCADE'), nullable=False)
    player_id = db.Column(db.Integer, db.ForeignKey('players.id', ondelete='CASCADE'), nullable=False)  # ✅ إضافة معرف اللاعب

    
    def __repr__(self):
        return f"UserClub('{self.id}', '{self.user_id}', '{self.club_id}')"

class UserPlayer(db.Model):
    __tablename__ = 'user_players'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    player_id = db.Column(db.Integer, db.ForeignKey('players.id', ondelete='CASCADE'), nullable=False)
    position = db.Column(db.String(50), nullable=False)  # الموقع في التشكيلة (مثل حارس مرمى، مدافع...)
    is_listed = db.Column(db.Boolean, default=False)
    price = db.Column(db.Integer)
    acquired_at = db.Column(db.DateTime, default=datetime.utcnow)
    sale_code = db.Column(db.String(6), unique=True, nullable=False)

    # العلاقات
    market_listing = db.relationship('UserMarketListing', backref='user_player', uselist=False, 
                                    foreign_keys='UserMarketListing.user_player_id')

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.sale_code:
            self.sale_code = generate_random_code()

    def __repr__(self):
        return f"UserPlayer('{self.id}', '{self.user_id}', '{self.player_id}', '{self.price}', '{self.sale_code}', '{self.position}')"


class ClubDetail(db.Model):
    __tablename__ = 'club_details'

    club_id = db.Column(db.Integer, primary_key=True)
    club_name = db.Column(db.String(100), nullable=False)
    founded_year = db.Column(db.Integer, nullable=False)
    coach_name = db.Column(db.String(100))
    club_image_url = db.Column(db.String(255))
    banner_image_url = db.Column(db.String(255))  # حقل البنر
    club_color = db.Column(db.String(7))  # حقل اللون (مثل #FFFFFF للون الأبيض)
    num_players = db.Column(db.Integer, default=0)  # يحدد عدد اللاعبين في النادي

    def __repr__(self):
        return f"ClubDetail('{self.club_id}', '{self.club_name}', '{self.coach_name}')"


class Subscription(db.Model):
    __tablename__ = 'subscriptions'  # تغيير اسم الجدول
    
    id = db.Column(db.Integer, primary_key=True)
    package_type = db.Column(db.String(100), nullable=False)  # نوع الاشتراك
    package_details = db.Column(db.Text, nullable=False)  # تفاصيل الاشتراك
    price = db.Column(db.Float, nullable=False)  # السعر
    is_outside_egypt = db.Column(db.Boolean, default=False)  # تحديد إذا كان الاشتراك خارج مصر
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # تاريخ الإنشاء
    
    # الجوائز والمميزات الجديدة
    coins_reward = db.Column(db.Integer, default=0)  # عدد الكوينز التي يكسبها المشترك
    daily_free_packs = db.Column(db.Integer, default=0)  # عدد الباكو المجانية في اليوم
    joker_players = db.Column(db.Integer, default=0)  # عدد لاعبي الجوكر الذين يكسبهم
    has_vip_badge = db.Column(db.Boolean, default=False)  # هل يحصل على شارة VIP في ملفه الشخصي
    has_vip_badge_plus = db.Column(db.Boolean, default=False)  # هل يحصل على شارة VIP plus في ملفه الشخصي
    subscription_achievement_coins = db.Column(db.Integer, default=0)  # كوينز إنجاز الاشتراك
    allow_old_ahly_catalog = db.Column(db.Boolean, default=False)  # السماح بجمع كتالوج النادي الأهلي القديم
    price_egp = db.Column(db.Float, nullable=False, default=0.0)  # السعر بالجنيه المصري
    price_usd = db.Column(db.Float, nullable=False, default=0.0)  # السعر بالدولار
    payment_link = db.Column(db.String(255), nullable=True)
    payment_link_usd = db.Column(db.String(255), nullable=True)


    def __repr__(self):
        return (f"Subscription(id={self.id}, package_type='{self.package_type}', "
                f"price={self.price}, is_outside_egypt={self.is_outside_egypt}, "
                f"coins_reward={self.coins_reward}, daily_free_packs={self.daily_free_packs}, "
                f"joker_players={self.joker_players}, has_vip_badge={self.has_vip_badge})")


                
# جدول لحفظ طلبات شراء الاشتراكات بدون روابط بين الجداول
class UserSubscriptionPurchase(db.Model):
    __tablename__ = 'user_subscription_purchases'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subscription_id = db.Column(db.Integer, db.ForeignKey('subscriptions.id'), nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Integer, default=0)  # السعر المدفوع
    username = db.Column(db.String(100), nullable=False)  # ✅ إضافة اسم المستخدم
    email = db.Column(db.String(120), nullable=False)  # ✅ إضافة البريد الإلكتروني
    country = db.Column(db.String(100), nullable=False)  # ✅ إضافة البلد
    status = db.Column(db.String(20), default='pending')
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime)
    payment_link = db.Column(db.String(255), nullable=True)
    
    def __repr__(self):
        return f"UserSubscriptionPurchase('{self.id}', '{self.user_id}', '{self.subscription_id}', '{self.status}', '{self.purchase_date}')"

class UserMarketListing(db.Model):
    __tablename__ = 'user_market_listings'
    
    id = db.Column(db.Integer, primary_key=True)
    user_player_id = db.Column(db.Integer, db.ForeignKey('user_players.id', ondelete='CASCADE'), nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    listed_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    status = db.Column(db.String(50), default='active')  # active, sold, expired, cancelled

    # العلاقات - تم تصحيح backref
    seller = db.relationship('User', backref='market_listings', lazy=True, foreign_keys=[seller_id])

    def __repr__(self):
        return f"UserMarketListing('{self.id}', '{self.price}', '{self.status}', '{self.seller_id}')"

class AdminMarketListing(db.Model):
    __tablename__ = 'admin_market_listings'
    
    id = db.Column(db.Integer, primary_key=True)
    player_id = db.Column(db.Integer, db.ForeignKey('players.id', ondelete='CASCADE'), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    listed_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    status = db.Column(db.String(50), default='active')  # active, sold, expired, cancelled
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)  # فقط الأدمن يمكنه إدراج اللاعبين

    # العلاقات
    admin = db.relationship('User', backref='admin_listings', lazy=True, foreign_keys=[admin_id])

    # دالة __repr__
    def __repr__(self):
        return f"AdminMarketListing('{self.id}', '{self.price}', '{self.status}', '{self.admin_id}')"

class Transaction(db.Model):
    __tablename__ = 'transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    buyer_id = db.Column(db.Integer,  nullable=False)
    seller_id = db.Column(db.Integer,  nullable=False)
    # Remove the foreign key constraint and keep only the integer column
    user_player_id = db.Column(db.Integer, nullable=True)  # Changed from ForeignKey to simple Integer
    listing_id = db.Column(db.Integer)  # معرف القائمة في السوق
    price = db.Column(db.Integer, nullable=False)
    transaction_date = db.Column(db.DateTime, default=datetime.utcnow)
    transaction_type = db.Column(db.String(50))  # market, pack_opening
    status = db.Column(db.String(50), default='completed')  # completed, failed, refunded
    payment_method = db.Column(db.String(50), default='coins')  # coins, subscription, etc

    def __repr__(self):
        return f"Transaction(id={self.id}, buyer_id={self.buyer_id}, price={self.price}, status={self.status})"

class Pack(db.Model):
    __tablename__ = 'packs'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(255))
    price = db.Column(db.Integer, nullable=False)
    player_count = db.Column(db.Integer, nullable=False)
    rarity_odds = db.Column(db.JSON)  # {'common': 70, 'rare': 20, 'epic': 8, 'legendary': 2}
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # العلاقات
    purchases = db.relationship('PackPurchase', backref='pack', lazy=True)

    # دالة __repr__
    def __repr__(self):
        return f"Pack('{self.id}', '{self.name}', '{self.price}', '{self.is_active}')"

class PackPurchase(db.Model):
    __tablename__ = 'pack_purchases'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    pack_id = db.Column(db.Integer, db.ForeignKey('packs.id', ondelete='CASCADE'), nullable=False)
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow)
    players_received = db.Column(db.JSON)  # [{'player_id': 1, 'rarity': 'rare'}, ...]
    price_paid = db.Column(db.Integer, nullable=False)

    # دالة __repr__
    def __repr__(self):
        return f"PackPurchase('{self.id}', '{self.price_paid}', '{self.purchase_date}')"

class Promotion(db.Model):
    __tablename__ = 'promotions'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(255))
    original_price = db.Column(db.Integer, nullable=False)
    discount_percentage = db.Column(db.Integer)  # نسبة الخصم
    final_price = db.Column(db.Integer, nullable=False)
    features = db.Column(db.JSON)  # قائمة المميزات ['feature1', 'feature2', ...]
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    promotion_type = db.Column(db.String(50))  # مثل: 'starter', 'golden', 'limited'
    coins_reward = db.Column(db.Integer, default=0)  # عدد العملات المجانية
    free_packs = db.Column(db.Integer, default=0)  # عدد الباكجات المجانية
    vip_duration_days = db.Column(db.Integer, default=0)  # مدة VIP بالأيام
    
    def __repr__(self):
        return f"Promotion('{self.name}', '{self.promotion_type}', '{self.final_price}')"

    @property
    def is_expired(self):
        if self.end_date:
            return datetime.utcnow() > self.end_date
        return False

    @property
    def remaining_time(self):
        if self.end_date:
            now = datetime.utcnow()
            if now < self.end_date:
                delta = self.end_date - now
                days = delta.days
                hours = delta.seconds // 3600
                minutes = (delta.seconds % 3600) // 60
                return {
                    'days': days,
                    'hours': hours,
                    'minutes': minutes
                }
        return None

class PaymentMethod(db.Model):
    __tablename__ = 'payment_methods'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    icon = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    is_egypt_only = db.Column(db.Boolean, default=False)
    wallet_number = db.Column(db.String(50))
    instructions = db.Column(db.Text)
    gateway_config = db.Column(db.Text)  # لتخزين إعدادات بوابة الدفع كـ JSON
    gateway_type = db.Column(db.String(50))  # paymob, fawry, stripe etc
    gateway_api_key = db.Column(db.String(512))
    gateway_integration_id = db.Column(db.String(255))
    gateway_iframe_id = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property 
    def decrypted_api_key(self):
        """Safely decrypt the API key"""
        try:
            if self.gateway_api_key:
                if isinstance(self.gateway_api_key, bytes):
                    return cipher_suite.decrypt(self.gateway_api_key).decode()
                return self.gateway_api_key
            return None
        except Exception as e:
            print(f"Warning: Error decrypting API key: {e}")
            return None

    def set_api_key(self, api_key):
        """Safely encrypt API key before storage"""
        try:
            if (api_key):
                self.gateway_api_key = cipher_suite.encrypt(
                    api_key.encode()
                )
        except Exception as e:
            print(f"Warning: Error encrypting API key: {e}")
            self.gateway_api_key = None

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'icon': self.icon,
            'is_active': self.is_active,
            'is_egypt_only': self.is_egypt_only,
            'wallet_number': self.wallet_number,
            'gateway_config': json.loads(self.gateway_config) if self.gateway_config else {},
            'instructions': self.instructions,
            'gateway_type': self.gateway_type,
            'gateway_api_key': self.decrypted_api_key,
            'gateway_integration_id': self.gateway_integration_id,
            'gateway_iframe_id': self.gateway_iframe_id
        }

class WalletRechargeOption(db.Model):
    __tablename__ = 'wallet_recharge_option'
    
    id = db.Column(db.Integer, primary_key=True)
    coins_amount = db.Column(db.Integer, nullable=False)
    price_egp = db.Column(db.Float, nullable=False)
    price_usd = db.Column(db.Float, nullable=False)
    payment_link = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'coins_amount': self.coins_amount,
            'price_egp': self.price_egp,
            'price_usd': self.price_usd,
            'payment_link': self.payment_link,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class WalletRechargeRequest(db.Model):
    __tablename__ = 'wallet_recharge_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('wallet_recharge_option.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)  # المبلغ المطلوب
    currency = db.Column(db.String(3), nullable=False)  # EGP or USD
    payment_method = db.Column(db.String(50), nullable=False)  # طريقة الدفع
    payment_link = db.Column(db.String(255))
    transaction_id = db.Column(db.String(100), unique=True, nullable=True)  # رقم العملية
    payment_proof = db.Column(db.String(255), nullable=True)  # رابط صورة إثبات الدفع
    status = db.Column(db.String(20), default='pending')  # pending, completed, rejected
    notes = db.Column(db.Text, nullable=True)  # ملاحظات إضافية
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # العلاقات
    user = db.relationship('User', backref='recharge_requests')
    option = db.relationship('WalletRechargeOption', backref='requests')
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'option_id': self.option_id,
            'amount': self.amount,
            'currency': self.currency,
            'payment_method': self.payment_method,
            'transaction_id': self.transaction_id,
            'payment_proof': self.payment_proof,
            'status': self.status,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

# إضافة index للبحث السريع
db.Index('idx_recharge_requests_user', WalletRechargeRequest.user_id)
db.Index('idx_recharge_requests_status', WalletRechargeRequest.status)

# إضافة index للبحث السريع
db.Index('idx_promotions_active', Promotion.is_active)
db.Index('idx_promotions_type', Promotion.promotion_type)

# Indexes for better query performance
db.Index('idx_user_players_user_id', UserPlayer.user_id)
db.Index('idx_market_listings_status', UserMarketListing.status)
db.Index('idx_transactions_date', Transaction.transaction_date)
db.Index('idx_pack_purchases_user_id', PackPurchase.user_id)

class ReferralCode(db.Model):
    __tablename__ = 'referral_codes'
    
    id = db.Column(db.Integer, primary_key=True)
    referrer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    referred_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    code_used = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, completed, expired
    
    # Relationships
    referrer = db.relationship('User', foreign_keys=[referrer_id], backref='referrals_made')
    referred = db.relationship('User', foreign_keys=[referred_id], backref='referral_info')

class ReferralReward(db.Model):
    __tablename__ = 'referral_rewards'
    
    id = db.Column(db.Integer, primary_key=True)
    referral_id = db.Column(db.Integer, db.ForeignKey('referral_codes.id'), nullable=False)
    coins_amount = db.Column(db.Integer, nullable=False)
    reward_type = db.Column(db.String(20))  # referrer_bonus, referred_bonus
    claimed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    referral = db.relationship('ReferralCode', backref='rewards')

# Add indexes for better performance
db.Index('idx_referral_codes_referrer', ReferralCode.referrer_id)
db.Index('idx_referral_codes_referred', ReferralCode.referred_id)
db.Index('idx_referral_codes_status', ReferralCode.status)
db.Index('idx_users_referral_code', User.referral_code)

class Beneficiary(db.Model):
    __tablename__ = 'beneficiaries'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    commission_rate = db.Column(db.Float, nullable=False) # Percentage (0-100)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationship with User
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', backref='beneficiary')

    def __repr__(self):
        return f'<Beneficiary {self.email}>'

class UnlimitedPlayer(db.Model):
    __tablename__ = 'unlimited_players'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    position = db.Column(db.String(50), nullable=False)  # GK, DEF, MID, ATT
    rating = db.Column(db.Integer, nullable=False)
    image_url = db.Column(db.String(255))
    club = db.Column(db.String(100))
    nationality = db.Column(db.String(100))
    price = db.Column(db.Integer, nullable=False)
    is_available = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Admin who added the player

    # Relationships
    team_positions = db.relationship('UnlimitedTeamPlayer', backref='player', lazy=True)
    match_events = db.relationship('UnlimitedMatchEvent', backref='player', lazy=True)

    def __repr__(self):
        return f"UnlimitedPlayer('{self.name}', '{self.position}', '{self.rating}')"

class UnlimitedTeam(db.Model):
    __tablename__ = 'unlimited_teams'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    formation = db.Column(db.String(10), default='4-3-3')  # e.g., 4-3-3, 4-4-2, etc.
    points = db.Column(db.Integer, default=0)  # Total points from match events
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    players = db.relationship('UnlimitedTeamPlayer', backref='team', lazy=True)
    user = db.relationship('User', backref='unlimited_team', lazy=True)

    def __repr__(self):
        return f"UnlimitedTeam('{self.name}', '{self.formation}', Points: {self.points})"

class UnlimitedTeamPlayer(db.Model):
    __tablename__ = 'unlimited_team_players'
    
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey('unlimited_teams.id'), nullable=False)
    player_id = db.Column(db.Integer, db.ForeignKey('unlimited_players.id'), nullable=False)
    position = db.Column(db.String(50), nullable=False)  # Specific position on field
    position_order = db.Column(db.Integer, nullable=False)  # Order in formation (1-11 for starters, 12-23 for subs)
    is_substitute = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"UnlimitedTeamPlayer(Team: {self.team_id}, Player: {self.player_id}, Position: {self.position})"

class UnlimitedMatchEvent(db.Model):
    __tablename__ = 'unlimited_match_events'
    
    id = db.Column(db.Integer, primary_key=True)
    player_id = db.Column(db.Integer, db.ForeignKey('unlimited_players.id'), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)  # goal, assist, yellow_card, red_card, etc.
    points = db.Column(db.Integer, nullable=False , default=0)  # Points to add/subtract
    match_info = db.Column(db.String(255))  # Information about the match
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Admin who added the event
    
    def __repr__(self):
        return f"UnlimitedMatchEvent(Player: {self.player_id}, Event: {self.event_type}, Points: {self.points})"

# Add indexes for better query performance
db.Index('idx_unlimited_team_user', UnlimitedTeam.user_id)
db.Index('idx_unlimited_team_player_team', UnlimitedTeamPlayer.team_id)
db.Index('idx_unlimited_team_player_player', UnlimitedTeamPlayer.player_id)
db.Index('idx_unlimited_match_event_player', UnlimitedMatchEvent.player_id)
