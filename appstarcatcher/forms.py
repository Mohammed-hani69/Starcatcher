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



class RegistrationForm(FlaskForm):
    username = StringField('اسم المستخدم', validators=[
        DataRequired(message='هذا الحقل مطلوب'),
        Length(min=3, max=80, message='يجب أن يكون اسم المستخدم بين 3 و 80 حرفاً')
    ])
    email = StringField('البريد الإلكتروني', validators=[
        DataRequired(message='هذا الحقل مطلوب'),
        Email(message='يرجى إدخال بريد إلكتروني صحيح')
    ])
    phone = StringField('رقم الهاتف', validators=[
        Optional(),
        Length(min=11, max=20, message='رقم الهاتف غير صحيح')
    ])
    country = StringField('الدولة', validators=[Optional()])
    state = StringField('المحافظة', validators=[Optional()])
    city = StringField('المدينة', validators=[Optional()])
    password = PasswordField('كلمة المرور', validators=[
        DataRequired(message='هذا الحقل مطلوب'),
        Length(min=6, message='يجب أن تكون كلمة المرور 6 أحرف على الأقل')
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

