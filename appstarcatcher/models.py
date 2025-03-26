from datetime import datetime
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from appstarcatcher import db  # استيراد db من التطبيق بدلاً من تعريفه هنا
import random
import string

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
    premuim = db.Column(db.Boolean, default=False)
    gold = db.Column(db.Boolean, default=False)
    subscription = db.Column(db.Boolean, default=False)
    type_subscription = db.Column(db.String(80), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    new_member_reward_collected = db.Column(db.Boolean, default=False)
    first_purchase_reward_collected = db.Column(db.Boolean, default=False)  # عمود جديد
    team_collector_reward_collected = db.Column(db.Boolean, default=False)  # Add this new column
    rare_expert_reward_collected = db.Column(db.Boolean, default=False)
    catalog_king_reward_collected = db.Column(db.Boolean, default=False)
    
    # العلاقات
    owned_players = db.relationship('UserPlayer', backref='owner', lazy=True, foreign_keys='UserPlayer.user_id')
    pack_purchases = db.relationship('PackPurchase', backref='user', lazy=True)
    user_clubs = db.relationship('UserClub', backref='user', lazy=True)

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
            if total_players == 0:
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


class Subscription(db.Model):  # تغيير اسم الجدول إلى "subscriptions"
    __tablename__ = 'subscriptions'  # تغيير اسم الجدول
    
    id = db.Column(db.Integer, primary_key=True)
    package_type = db.Column(db.String(100), nullable=False)  # نوع الاشتراك
    package_details = db.Column(db.Text, nullable=False)  # تفاصيل الاشتراك
    price = db.Column(db.Float, nullable=False)  # السعر
    is_outside_egypt = db.Column(db.Boolean, default=False)  # تحديد إذا كان الاشتراك خارج مصر
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # تاريخ الإنشاء
    def __repr__(self):
        return f"Subscription('{self.id}', '{self.package_type}', '{self.price}', '{self.is_outside_egypt}')"

# جدول لحفظ طلبات شراء الاشتراكات بدون روابط بين الجداول
class UserSubscriptionPurchase(db.Model):
    __tablename__ = 'user_subscription_purchases'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)  # معرف المستخدم الذي اشترى الاشتراك
    subscription_id = db.Column(db.Integer, nullable=False)  # معرف الاشتراك الذي تم شراؤه
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow)  # تاريخ شراء الاشتراك
    status = db.Column(db.String(50), default='active')  # حالة الاشتراك مثل 'active', 'expired', 'cancelled'
    expiry_date = db.Column(db.DateTime, nullable=False)

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

# Indexes for better query performance
db.Index('idx_user_players_user_id', UserPlayer.user_id)
db.Index('idx_market_listings_status', UserMarketListing.status)
db.Index('idx_transactions_date', Transaction.transaction_date)
db.Index('idx_pack_purchases_user_id', PackPurchase.user_id)
