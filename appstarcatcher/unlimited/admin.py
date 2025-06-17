from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, current_app
from flask_login import login_required, current_user
from appstarcatcher import db
from appstarcatcher.models import UnlimitedPlayer
from werkzeug.utils import secure_filename
import os

admin = Blueprint('admin', __name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@admin.route('/players', methods=['GET', 'POST'])
@login_required
def manage_players():
    if not current_user.is_admin:
        flash('غير مصرح بالوصول', 'danger')
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        try:
            # التحقق من البيانات المطلوبة
            if not all(field in request.form for field in ['name', 'position', 'rating', 'club', 'nationality']):
                return jsonify({'success': False, 'message': 'جميع الحقول مطلوبة'}), 400
            
            # معالجة الصورة
            image_url = None
            if 'image' in request.files:
                file = request.files['image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    # إنشاء مجلد الصور إذا لم يكن موجوداً
                    upload_folder = os.path.join(current_app.static_folder, 'uploads', 'unlimited')
                    if not os.path.exists(upload_folder):
                        os.makedirs(upload_folder)
                    
                    # حفظ الصورة مع اسم فريد
                    unique_filename = f"{os.path.splitext(filename)[0]}_{hash(os.urandom(8))}{os.path.splitext(filename)[1]}"
                    file_path = os.path.join(upload_folder, unique_filename)
                    file.save(file_path)
                    image_url = f'uploads/unlimited/{unique_filename}'
            
            # إنشاء لاعب جديد
            player = UnlimitedPlayer(
                name=request.form['name'],
                position=request.form['position'],
                rating=int(request.form['rating']),
                club=request.form['club'],
                nationality=request.form['nationality'],
                image_url=image_url,
                created_by=current_user.id
            )
            
            db.session.add(player)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'تم إضافة اللاعب بنجاح',
                'player': {
                    'id': player.id,
                    'name': player.name,
                    'position': player.position,
                    'rating': player.rating,
                    'club': player.club,
                    'nationality': player.nationality,
                    'image_url': player.image_url
                }
            })
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error adding player: {str(e)}")
            return jsonify({'success': False, 'message': 'حدث خطأ أثناء إضافة اللاعب'}), 500
    
    # عرض قائمة اللاعبين
    players = UnlimitedPlayer.query.order_by(UnlimitedPlayer.created_at.desc()).all()
    return render_template('unlimited/admin/manage_players.html', 
                         players=players)

@admin.route('/players/<int:player_id>', methods=['DELETE'])
@login_required
def delete_player(player_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'غير مصرح بالوصول'}), 403
    
    try:
        player = UnlimitedPlayer.query.get_or_404(player_id)
        
        # حذف الصورة إذا كانت موجودة
        if player.image_url:
            image_path = os.path.join(current_app.static_folder, player.image_url)
            if os.path.exists(image_path):
                os.remove(image_path)
        
        db.session.delete(player)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'تم حذف اللاعب بنجاح'})
    
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting player: {str(e)}")
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء حذف اللاعب'}), 500
