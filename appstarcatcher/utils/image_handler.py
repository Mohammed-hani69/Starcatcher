import os
from PIL import Image
from pillow_heif import register_heif_opener
from werkzeug.utils import secure_filename

# تسجيل دعم صور HEIF/HEIC
register_heif_opener()

# القيم الافتراضية
MAX_IMAGE_SIZE = (1920, 1080)  # الحد الأقصى لأبعاد الصورة
JPEG_QUALITY = 85  # جودة ضغط JPEG
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'heic', 'heif', 'webp'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 ميجابايت

def is_valid_image(file):
    """التحقق من أن الملف هو صورة صالحة"""
    try:
        # Get file extension
        filename = file.filename
        if not '.' in filename:
            return False
            
        ext = filename.rsplit('.', 1)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            return False

        # Try to open the image with PIL
        img = Image.open(file)
        img.verify()
        file.seek(0)  # Reset file pointer
        return True
    except Exception:
        return False

def optimize_image(image_data, output_path, max_size=MAX_IMAGE_SIZE, quality=JPEG_QUALITY):
    """تحسين الصورة وحفظها"""
    try:
        # فتح الصورة
        img = Image.open(image_data)
        
        # تحويل الصورة إلى RGB إذا كانت RGBA
        if img.mode in ('RGBA', 'LA'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            background.paste(img, mask=img.split()[-1])
            img = background
        
        # تغيير حجم الصورة إذا كانت أكبر من الحد الأقصى
        if img.size[0] > max_size[0] or img.size[1] > max_size[1]:
            img.thumbnail(max_size, Image.Resampling.LANCZOS)
        
        # حفظ الصورة بتنسيق JPEG مع الضغط
        img.save(output_path, 'JPEG', quality=quality, optimize=True)
        return True
    except Exception as e:
        print(f"Error optimizing image: {str(e)}")
        return False

def save_image(file, upload_folder, filename=None):
    """حفظ الصورة مع التحسين"""
    try:
        if not is_valid_image(file):
            raise ValueError("الملف ليس صورة صالحة")
        
        if not filename:
            filename = secure_filename(file.filename)
        
        # إنشاء اسم الملف النهائي
        base_name = os.path.splitext(filename)[0]
        final_filename = f"{base_name}.jpg"  # تحويل جميع الصور إلى JPEG
        output_path = os.path.join(upload_folder, final_filename)
        
        # تحسين وحفظ الصورة
        if optimize_image(file, output_path):
            return final_filename
        return None
    except Exception as e:
        print(f"Error saving image: {str(e)}")
        return None

def delete_image(filename, upload_folder):
    """حذف الصورة من المجلد"""
    try:
        file_path = os.path.join(upload_folder, filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
        return False
    except Exception as e:
        print(f"Error deleting image: {str(e)}")
        return False
