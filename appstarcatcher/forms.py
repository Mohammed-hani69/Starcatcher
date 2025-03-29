from datetime import datetime
from flask_wtf import FlaskForm
from appstarcatcher import db
from wtforms import BooleanField, DateTimeField, FloatField, PasswordField, StringField, IntegerField, SelectField, SubmitField, TextAreaField, ValidationError
from wtforms.validators import DataRequired, Optional, NumberRange, Length ,  Email , EqualTo
from flask_wtf.file import FileField, FileAllowed

from appstarcatcher.models import Player, User

class PlayerForm(FlaskForm):
    name = StringField('اسم اللاعب', validators=[DataRequired(), Length(min=1, max=80)])
    rating = IntegerField('التقييم', validators=[DataRequired(), NumberRange(min=1, max=99)])
    
    # إضافة اختيار المراكز
    position = SelectField('المركز', choices=[
        ('GK', 'حارس مرمى'),
        ('RB', 'مدافع أيمن'),
        ('CB1', 'مدافع وسط 1'),
        ('CB2', 'مدافع وسط 2'),
        ('LB', 'مدافع أيسر'),
        ('DMF', 'وسط دفاعي'),
        ('CMF', 'وسط مبدع'),
        ('AMF', 'وسط مهاجم'),
        ('RW', 'جناح أيمن'),
        ('LW', 'جناح أيسر'),
        ('CF', 'مهاجم'),
        ('president', 'رئيس النادي'),
        ('goalkeeper_coach', 'مدرب الحراس'),
        ('coach', 'المدرب'),
        ('assistant_coach', 'مساعد المدرب'),
    ], validators=[DataRequired()])
    
    image_url = FileField('صورة اللاعب', validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'الصور فقط!'), Optional()])
    rarity = StringField('النُدرة', validators=[DataRequired()])
    nationality = StringField('الجنسية', validators=[DataRequired(), Length(max=100)])
    club = SelectField('النادي', choices=[], validators=[DataRequired()])
    
    submit = SubmitField('إضافة اللاعب')





class PackForm(FlaskForm):
    name = StringField('اسم الباكج', validators=[
        DataRequired(message='يجب إدخال اسم الباكج'),
        Length(max=100, message='يجب أن لا يتجاوز الاسم 100 حرف')
    ])
    description = TextAreaField('الوصف', validators=[
        DataRequired(message='يجب إدخال وصف الباكج')
    ])
    price = IntegerField('السعر', validators=[
        DataRequired(message='يجب إدخال السعر'),
        NumberRange(min=0, message='يجب أن يكون السعر أكبر من صفر')
    ])
    player_count = IntegerField('عدد اللاعبين', validators=[
        DataRequired(message='يجب إدخال عدد اللاعبين'),
        NumberRange(min=1, message='يجب أن يكون عدد اللاعبين أكبر من صفر')
    ])
    image = FileField('صورة الباكج')
    is_active = BooleanField('تفعيل الباكج', default=True)

countries = [
        ('', 'اختر دولة'),  # هذا الخيار يستخدم كخيار افتراضي (اختياري)
        ('eg', 'مصر'),
        ('sa', 'السعودية'),
        ('ae', 'الإمارات'),
        ('jo', 'الأردن'),
        # يمكنك إضافة المزيد من الدول هنا
    ]

def password_check(form, field):
    password = field.data
    if len(password) < 8:
        raise ValidationError('يجب أن تكون كلمة المرور 8 أحرف على الأقل')
  #  if not any(char.isdigit() for char in password):
   #     raise ValidationError('يجب أن تحتوي كلمة المرور على رقم واحد على الأقل')
    #if not any(char.isupper() for char in password):
     #   raise ValidationError('يجب أن تحتوي كلمة المرور على حرف كبير واحد على الأقل')
    #if not any(char.islower() for char in password):
     #   raise ValidationError('يجب أن تحتوي كلمة المرور على حرف صغير واحد على الأقل')
    #if not any(char in '!@#$%^&*()_+-={}[]|:;<>,.?' for char in password):
     #   raise ValidationError('يجب أن تحتوي كلمة المرور على رمز خاص واحد على الأقل')

class RegistrationForm(FlaskForm):
    username = StringField('اسمك كامل', validators=[
        DataRequired(message='هذا الحقل مطلوب'),
        Length(min=3, max=80, message='يجب أن يكون اسمك بين 3 و 80 حرفاً')
    ])
    email = StringField('البريد الإلكتروني', validators=[
        DataRequired(message='هذا الحقل مطلوب'),
        Email(message='يرجى إدخال بريد إلكتروني صحيح')
    ])
    phone = StringField('رقم الهاتف', validators=[
        Optional(),
        Length(min=11, max=20, message='رقم الهاتف غير صحيح')
    ])
    country = SelectField('الدولة', choices=countries, validators=[Optional()])
    state = StringField('المحافظة', validators=[Optional()])
    city = StringField('المدينة', validators=[Optional()])
    password = PasswordField('كلمة المرور', validators=[
        DataRequired(message='هذا الحقل مطلوب'),
        Length(min=8, message='يجب أن تكون كلمة المرور 8 أحرف على الأقل'),
        password_check
    ])
    confirm_password = PasswordField('تأكيد كلمة المرور', validators=[
        DataRequired(message='هذا الحقل مطلوب'),
        EqualTo('password', message='كلمة المرور غير متطابقة')
    ])
    profile_image = FileField('الصورة الشخصية', validators=[
        FileAllowed(['jpg', 'png', 'jpeg'], 'يسمح فقط بملفات الصور')
    ])
    submit = SubmitField('تسجيل')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('اسم المستخدم مستخدم بالفعل')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data.lower()).first()
        if user:
            raise ValidationError('البريد الإلكتروني مستخدم بالفعل')

    def validate_phone(self, phone):
        if phone.data:
            user = User.query.filter_by(phone=phone.data).first()
            if user:
                raise ValidationError('رقم الهاتف مستخدم بالفعل')

class LoginForm(FlaskForm):
    email = StringField('البريد الإلكتروني', 
        validators=[
            DataRequired(message='هذا الحقل مطلوب'),
            Email(message='يرجى إدخال بريد إلكتروني صحيح')
        ])
    password = PasswordField('كلمة المرور',
        validators=[
            DataRequired(message='هذا الحقل مطلوب')
        ])
    remember = BooleanField('تذكرني')
    submit = SubmitField('دخول')
    
    def validate_email(self, field):
        # Convert to lowercase and strip whitespace
        field.data = field.data.lower().strip()


class AdminMarketListingForm(FlaskForm):
    # حقل لتحديد اللاعب من قاعدة البيانات
    player_id = SelectField('اسم اللاعب', coerce=int, validators=[DataRequired()])
    
    # تحديد السعر
    price = IntegerField('السعر', validators=[DataRequired(), NumberRange(min=1, message="السعر يجب أن يكون أكبر من 0")])

    # تحديد تاريخ انتهاء العرض (يمكن اختيار التاريخ من التقويم)
    expires_at = DateTimeField('تاريخ الانتهاء', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])

    # تحديد الحالة (نشط، مبيع، منتهي، ملغى)
    status = SelectField('الحالة', choices=[('active', 'نشط'), ('sold', 'مباع'), ('expired', 'منتهي'), ('cancelled', 'ملغى')], 
                         validators=[DataRequired()])

    def __init__(self, *args, **kwargs):
        super(AdminMarketListingForm, self).__init__(*args, **kwargs)
        
        # استرجاع اللاعبين من قاعدة البيانات
        players = db.session.query(Player).all()
        self.player_id.choices = [(player.id, player.name) for player in players]


class SubscriptionForm(FlaskForm):
    package_type = StringField('نوع الاشتراك', validators=[DataRequired()])
    package_details = TextAreaField('تفاصيل الاشتراك', validators=[DataRequired()])
    price = FloatField('السعر', validators=[DataRequired()])
    is_outside_egypt = BooleanField('هل الاشتراك خارج مصر؟', default=False)
    
    # الجوائز والمميزات الجديدة
    coins_reward = IntegerField('عدد الكوينز المكتسبة', default=0, validators=[DataRequired()])
    daily_free_packs = IntegerField('عدد الباكو المجانية يوميًا', default=0, validators=[DataRequired()])
    joker_players = IntegerField('عدد لاعبي الجوكر', default=0, validators=[DataRequired()])
    has_vip_badge = BooleanField('شارة VIP', default=False)
    has_vip_badge_plus = BooleanField('شارة VIP Plus', default=False)
    subscription_achievement_coins = IntegerField('كوينز إنجاز الاشتراك', default=0, validators=[DataRequired()])
    allow_old_ahly_catalog = BooleanField('السماح بكتالوج الأهلي القديم', default=False)

    submit = SubmitField('إضافة الاشتراك') 


    
class ClubForm(FlaskForm):
    club_name = StringField('اسم النادي', validators=[DataRequired()])
    founded_year = IntegerField('سنة التأسيس', validators=[
        DataRequired(),
        NumberRange(min=1800, max=datetime.now().year)
    ])
    coach_name = StringField('اسم المدرب', validators=[DataRequired()])
    club_image = FileField('شعار النادي')
    banner_image = FileField('صورة البنر')  # حقل لتحميل صورة البنر
    club_color = StringField('لون النادي (كود HEX)', validators=[DataRequired()])  # حقل لتحديد اللون
    num_players = IntegerField('عدد اللاعبين', validators=[DataRequired(), NumberRange(min=0)])

    submit = SubmitField('إضافة النادي')

class PromotionForm(FlaskForm):
    name = StringField('اسم العرض', validators=[DataRequired()])
    description = TextAreaField('وصف العرض', validators=[DataRequired()])
    image = FileField('صورة العرض', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    original_price = IntegerField('السعر الأصلي', validators=[DataRequired(), NumberRange(min=0)])
    discount_percentage = IntegerField('نسبة الخصم (%)', validators=[NumberRange(min=0, max=100)])
    final_price = IntegerField('السعر النهائي', validators=[DataRequired(), NumberRange(min=0)])
    promotion_type = SelectField('نوع العرض', choices=[
        ('starter', 'عرض البداية'),
        ('golden', 'العرض الذهبي'),
        ('limited', 'عرض محدود')
    ])
    coins_reward = IntegerField('العملات المجانية', validators=[NumberRange(min=0)])
    free_packs = IntegerField('عدد الباكجات المجانية', validators=[NumberRange(min=0)])
    vip_duration_days = IntegerField('مدة VIP (بالأيام)', validators=[NumberRange(min=0)])
    end_date = DateTimeField('تاريخ انتهاء العرض', format='%Y-%m-%dT%H:%M')

