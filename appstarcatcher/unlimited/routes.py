from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from appstarcatcher import db
from flask import current_app as app
from appstarcatcher.models import UnlimitedPlayer, UnlimitedTeam, UnlimitedTeamPlayer, UnlimitedMatchEvent
from datetime import datetime
from werkzeug.utils import secure_filename
import os

unlimited = Blueprint('unlimited', __name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_position_name(position, is_substitute):
    """Validate that a position name follows expected format"""
    if is_substitute:
        if not position or not position.startswith('SUB') or not position[3:].isdigit():
            raise ValueError('Invalid substitute position name')
        sub_num = int(position[3:])
        if sub_num < 1 or sub_num > 7:
            raise ValueError('Invalid substitute position number')
    else:
        valid_field_positions = ['GK', 'LB', 'CB1', 'CB2', 'RB', 'LM', 'CM', 'RM', 'LW', 'ST', 'RW']
        if position not in valid_field_positions:
            raise ValueError('Invalid field position name')

def get_next_sub_position(team_id):
    """Get the next available SUB position number"""
    used_positions = {
        int(p.position[3:])
        for p in UnlimitedTeamPlayer.query.filter_by(
            team_id=team_id,
            is_substitute=True
        ).all()
        if p.position and p.position.startswith('SUB') and p.position[3:].isdigit()
    }
    
    for i in range(1, 8):
        if i not in used_positions:
            return f'SUB{i}'
    return None

@unlimited.route('/')
@login_required
def index():
    """Main page of the unlimited section"""
    return redirect(url_for('unlimited.team'))

@unlimited.route('/market')
@login_required
def market():
    """Display the unlimited market where players can be purchased"""
    players = UnlimitedPlayer.query.filter_by(is_available=True).all()
    return render_template('unlimited/market.html', players=players)

@unlimited.route('/team')
@login_required
def team():
    """Display the user's team management page"""
    user_team = UnlimitedTeam.query.filter_by(user_id=current_user.id).first()
    if not user_team:
        user_team = UnlimitedTeam(
            user_id=current_user.id,
            name=f"{current_user.username}'s Team",
            formation="4-3-3"
        )
        db.session.add(user_team)
        db.session.commit()
    
    team_players = UnlimitedTeamPlayer.query.filter_by(team_id=user_team.id).all()
    available_players = UnlimitedPlayer.query.join(UnlimitedTeamPlayer).filter(
        UnlimitedTeamPlayer.team_id == user_team.id
    ).all()
    
    # Formation positions for 4-3-3
    formation_positions = {
        'GK': {'x': 10, 'y': 50},
        'LB': {'x': 20, 'y': 20},
        'CB1': {'x': 20, 'y': 40},
        'CB2': {'x': 20, 'y': 60},
        'RB': {'x': 20, 'y': 80},
        'LM': {'x': 40, 'y': 20},
        'CM': {'x': 40, 'y': 50},
        'RM': {'x': 40, 'y': 80},
        'LW': {'x': 70, 'y': 20},
        'ST': {'x': 70, 'y': 50},
        'RW': {'x': 70, 'y': 80}
    }
    
    # Position names in Arabic
    position_names = {
        'GK': 'حارس مرمى',
        'LB': 'ظهير أيسر',
        'CB1': 'قلب دفاع 1',
        'CB2': 'قلب دفاع 2',
        'RB': 'ظهير أيمن',
        'LM': 'وسط أيسر',
        'CM': 'وسط مركزي',
        'RM': 'وسط أيمن',
        'LW': 'جناح أيسر',
        'ST': 'رأس حربة',
        'RW': 'جناح أيمن',
        'SUB1': 'بديل 1',
        'SUB2': 'بديل 2',
        'SUB3': 'بديل 3',
        'SUB4': 'بديل 4',
        'SUB5': 'بديل 5',
        'SUB6': 'بديل 6',
        'SUB7': 'بديل 7'
    }
    
    return render_template('unlimited/unlimited_team.html', 
                         team=user_team, 
                         team_players=team_players,
                         available_players=available_players,
                         formation_positions=formation_positions,
                         position_names=position_names)

@unlimited.route('/unlimited/update_formation', methods=['POST'])
@login_required
def update_formation():
    """Update player positions in formation"""
    data = request.json
    team_id = data.get('team_id')
    positions = data.get('positions')  # List of {player_id, position, is_substitute, order}
    
    team = UnlimitedTeam.query.get_or_404(team_id)
    if team.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        # First, collect all current bench players to track SUB positions
        current_subs = {
            p.position: True 
            for p in UnlimitedTeamPlayer.query.filter_by(team_id=team_id, is_substitute=True).all()
            if p.position and p.position.startswith('SUB')
        }
        
        for pos in positions:
            player = UnlimitedTeamPlayer.query.filter_by(
                team_id=team_id,
                player_id=pos['player_id']
            ).first()
            
            if player:
                if pos['is_substitute']:
                    # For bench players, assign next available SUB position
                    sub_pos = get_next_sub_position(team_id)
                    if sub_pos:
                        player.position = sub_pos
                        current_subs[sub_pos] = True
                    else:
                        # If no SUB position available, reject the move
                        return jsonify({'error': 'No substitute positions available'}), 400
                    
                    player.position_order = 12 + len(current_subs)
                else:
                    # For field players, use the exact position sent
                    player.position = pos['position']
                    player.position_order = pos['order']
                
                # Always update substitute status
                player.is_substitute = pos['is_substitute']
                
                # Remove old SUB position if player was a sub
                if (not pos['is_substitute'] and 
                    player.position in current_subs):
                    current_subs.pop(player.position, None)
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Formation updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@unlimited.route('/unlimited/substitute_player', methods=['POST'])
@login_required
def substitute_player():
    """Substitute a player from bench with playing player"""
    data = request.json
    team_id = data.get('team_id')
    player_out_id = data.get('player_out')
    player_in_id = data.get('player_in')
    
    team = UnlimitedTeam.query.get_or_404(team_id)
    if team.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        player_out = UnlimitedTeamPlayer.query.filter_by(
            team_id=team_id,
            player_id=player_out_id
        ).first()
        player_in = UnlimitedTeamPlayer.query.filter_by(
            team_id=team_id,
            player_id=player_in_id
        ).first()
        
        if not player_out or not player_in:
            return jsonify({'error': 'Players not found'}), 404
            
        # Validate both players' positions
        if not player_out.position or player_out.is_substitute:
            return jsonify({'error': 'Field player not found'}), 400
        if not player_in.position or not player_in.is_substitute:
            return jsonify({'error': 'Bench player not found'}), 400
            
        # Remember field position
        field_position = player_out.position
        field_order = player_out.position_order
        
        # Get next available SUB position for field player going to bench
        sub_position = get_next_sub_position(team_id)
        if not sub_position:
            return jsonify({'error': 'No substitute positions available'}), 400
            
        # Update the players
        player_out.position = sub_position
        player_out.is_substitute = True
        player_out.position_order = 12 + int(sub_position[3:])
        
        player_in.position = field_position
        player_in.is_substitute = False
        player_in.position_order = field_order
        
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'Players substituted successfully',
            'player_out': {
                'id': player_out.player_id,
                'position': sub_position
            },
            'player_in': {
                'id': player_in.player_id,
                'position': field_position
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

# Admin routes
@unlimited.route('/admin/players', methods=['GET', 'POST'])
@login_required
def admin_players():
    """Admin interface for managing unlimited players"""
    if not current_user.is_admin:
        flash('غير مصرح بالوصول', 'danger')
        return redirect(url_for('main.index'))
        
    if request.method == 'POST':
        name = request.form.get('name')
        position = request.form.get('position')
        rating = request.form.get('rating')
        club = request.form.get('club')
        nationality = request.form.get('nationality')
        price = request.form.get('price')
        
        # التعامل مع الصورة
        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                upload_folder = os.path.join(app.root_path, 'static', 'uploads', 'unlimited')
                
                # إنشاء المجلد إذا لم يكن موجوداً
                if not os.path.exists(upload_folder):
                    os.makedirs(upload_folder)
                    
                filepath = os.path.join(upload_folder, filename)
                file.save(filepath)
                image_url = f'/static/uploads/unlimited/{filename}'
        
        player = UnlimitedPlayer(
            name=name,
            position=position,
            rating=rating,
            club=club,
            nationality=nationality,
            price=price,
            image_url=image_url,
            created_by=current_user.id
        )
        
        try:
            db.session.add(player)
            db.session.commit()
            flash('تم إضافة اللاعب بنجاح', 'success')
            return redirect(url_for('unlimited.admin_players'))
        except Exception as e:
            db.session.rollback()
            flash(f'حدث خطأ أثناء إضافة اللاعب: {str(e)}', 'danger')
        
    players = UnlimitedPlayer.query.order_by(UnlimitedPlayer.id.desc()).all()
    return render_template('unlimited/admin_players.html', 
                         players=players, 
                         username=current_user.username)

@unlimited.route('/admin/events', methods=['GET', 'POST'])
@login_required
def admin_events():
    """Admin interface for managing match events"""
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        player_id = request.form.get('player_id')
        event_type = request.form.get('event_type')
        match_info = request.form.get('match_info')
        
        # تحديد النقاط بناءً على نوع الحدث
        points_map = {
            'goal': 3,
            'assist': 2,
            'clean_sheet': 2,
            'yellow_card': -1,
            'red_card': -3,
            'own_goal': -2
        }
        
        points = points_map.get(event_type, 0)
        
        event = UnlimitedMatchEvent(
            player_id=player_id,
            event_type=event_type,
            points=points,
            match_info=match_info,
            created_by=current_user.id
        )
        
        # Update team points
        player_teams = UnlimitedTeamPlayer.query.filter_by(player_id=player_id).all()
        for player_team in player_teams:
            team = UnlimitedTeam.query.get(player_team.team_id)
            team.points += int(points)
        
        db.session.add(event)
        db.session.commit()
        flash('Event added successfully', 'success')
        
    players = UnlimitedPlayer.query.all()
    events = UnlimitedMatchEvent.query.order_by(UnlimitedMatchEvent.created_at.desc()).all()
    return render_template('unlimited/admin_events.html', players=players, username=current_user.username, events=events)

@unlimited.route('/add_player', methods=['POST'])
@login_required
def add_player():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    try:
        # تحقق من وجود جميع البيانات المطلوبة
        required_fields = ['name', 'position', 'rating', 'club', 'price']
        for field in required_fields:
            if field not in request.form:
                return jsonify({
                    'success': False,
                    'message': f'Missing required field: {field}'
                }), 400

        # تحقق من وجود الصورة
        if 'image' not in request.files:
            return jsonify({
                'success': False,
                'message': 'No image file provided'
            }), 400

        file = request.files['image']
        if not file or file.filename == '':
            return jsonify({
                'success': False,
                'message': 'No image selected'
            }), 400

        if not allowed_file(file.filename):
            return jsonify({
                'success': False,
                'message': 'Invalid file type. Allowed types: ' + ', '.join(ALLOWED_EXTENSIONS)
            }), 400

        # إنشاء اسم فريد للملف باستخدام الوقت الحالي
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        original_filename = secure_filename(file.filename)
        filename = f"{timestamp}_{original_filename}"

        # إنشاء مسار المجلد إذا لم يكن موجوداً
        upload_folder = os.path.join(app.root_path, 'static', 'uploads', 'unlimited')
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        # حفظ الملف
        filepath = os.path.join(upload_folder, filename)
        file.save(filepath)

        # إنشاء رابط الصورة النسبي
        image_url = f'/static/uploads/unlimited/{filename}'

        # إنشاء اللاعب مع جميع البيانات
        player = UnlimitedPlayer(
            name=request.form['name'],
            position=request.form['position'],
            rating=int(request.form['rating']),
            club=request.form['club'],
            price=int(request.form['price']),
            nationality=request.form.get('nationality'),  # حقل اختياري
            image_url=image_url,
            created_by=current_user.id,
            is_available=True
        )

        # حفظ في قاعدة البيانات
        db.session.add(player)
        db.session.commit()

        # إرجاع النتيجة مع بيانات اللاعب
        return jsonify({
            'success': True,
            'message': 'تم إضافة اللاعب بنجاح',
            'player': {
                'id': player.id,
                'name': player.name,
                'position': player.position,
                'rating': player.rating,
                'club': player.club,
                'price': player.price,
                'image_url': player.image_url
            }
        })

    except Exception as e:
        # التراجع عن التغييرات في حالة حدوث خطأ
        db.session.rollback()
        
        # إزالة الملف إذا تم حفظه
        if 'filepath' in locals():
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except:
                pass  # تجاهل أي أخطاء في حذف الملف
                
        return jsonify({
            'success': False,
            'message': f'حدث خطأ أثناء إضافة اللاعب: {str(e)}'
        }), 400

@unlimited.route('/buy_player', methods=['POST'])
@login_required
def buy_player():
    try:
        data = request.get_json()
        player_id = data.get('player_id')
        
        player = UnlimitedPlayer.query.get_or_404(player_id)
        if not player.is_available:
            return jsonify({'success': False, 'message': 'Player is not available'})
            
        team = UnlimitedTeam.query.filter_by(user_id=current_user.id).first()
        if not team:
            return jsonify({'success': False, 'message': 'You need to create a team first'})
            
        # Check if user can afford the player
        if current_user.coins < player.price:
            return jsonify({'success': False, 'message': 'Insufficient coins'})
            
        # Check if team has space for another player
        existing_players = UnlimitedTeamPlayer.query.filter_by(team_id=team.id).count()
        if existing_players >= 23:  # 11 main + 12 subs
            return jsonify({'success': False, 'message': 'Team is full'})
            
        # Create team player entry
        team_player = UnlimitedTeamPlayer(
            team_id=team.id,
            player_id=player_id,
            position=player.position,
            position_order=existing_players + 1,
            is_substitute=True
        )
        
        # Deduct coins
        current_user.coins -= player.price
        
        db.session.add(team_player)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Player purchased successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@unlimited.route('/get_team')
@login_required
def get_team():
    team = UnlimitedTeam.query.filter_by(user_id=current_user.id).first()
    if not team:
        return jsonify({'success': False, 'message': 'Team not found'})
        
    team_players = UnlimitedTeamPlayer.query.filter_by(team_id=team.id).all()
    players_data = []
    
    for tp in team_players:
        player = UnlimitedPlayer.query.get(tp.player_id)
        players_data.append({
            'id': player.id,
            'name': player.name,
            'position': tp.position,
            'rating': player.rating,
            'image_url': player.image_url,
            'position_order': tp.position_order,
            'is_substitute': tp.is_substitute
        })
    
    return jsonify({
        'success': True,
        'team': {
            'id': team.id,
            'name': team.name,
            'formation': team.formation,
            'points': team.points
        },
        'players': players_data
    })

@unlimited.route('/make_substitution', methods=['POST'])
@login_required
def make_substitution():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400

        player_id = data.get('player_id')
        new_position = data.get('new_position')
        position_order = data.get('position_order')

        # Validate input types
        if not all([player_id, new_position, isinstance(position_order, int) or str(position_order).isdigit()]):
            return jsonify({'success': False, 'message': 'Invalid input data'}), 400

        position_order = int(position_order)

        # Get user's team
        team = UnlimitedTeam.query.filter_by(user_id=current_user.id).first()
        if not team:
            return jsonify({'success': False, 'message': 'Team not found'}), 404

        # Find the player to substitute in
        player = UnlimitedTeamPlayer.query.filter_by(team_id=team.id, player_id=player_id).first()
        if not player:
            return jsonify({'success': False, 'message': 'Player not found in your team'}), 404

        # Check if there's already a player in the target position
        existing_player = UnlimitedTeamPlayer.query.filter_by(
            team_id=team.id,
            position=new_position,
            position_order=position_order,
            is_substitute=False
        ).first()

        if existing_player and existing_player.player_id != player_id:
            # Make the existing player a substitute
            max_sub_order = db.session.query(
                db.func.max(UnlimitedTeamPlayer.position_order)
            ).filter_by(team_id=team.id, is_substitute=True).scalar()

            existing_player.is_substitute = True
            existing_player.position = None
            existing_player.position_order = (max_sub_order or 11) + 1

        # Update the incoming player's position
        player.position = new_position
        player.position_order = position_order
        player.is_substitute = False

        db.session.commit()
        return jsonify({'success': True, 'message': 'Substitution made successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error occurred: {str(e)}'}), 500


@unlimited.route('/player_details/<int:player_id>')
@login_required
def player_details(player_id):
    player = UnlimitedPlayer.query.get_or_404(player_id)
    events = UnlimitedMatchEvent.query.filter_by(player_id=player_id)\
        .order_by(UnlimitedMatchEvent.created_at.desc())\
        .limit(5)\
        .all()
        
    events_data = [{
        'event_type': event.event_type,
        'points': event.points,
        'match_info': event.match_info,
        'created_at': event.created_at.isoformat()
    } for event in events]
    
    return jsonify({
        'success': True,
        'player': {
            'id': player.id,
            'name': player.name,
            'position': player.position,
            'rating': player.rating,
            'club': player.club,
            'image_url': player.image_url
        },
        'events': events_data
    })

@unlimited.route('/search_players')
@login_required
def search_players():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    query = request.args.get('q', '')
    players = UnlimitedPlayer.query.filter(
        UnlimitedPlayer.name.ilike(f'%{query}%')
    ).all()
    
    return jsonify({
        'success': True,
        'players': [{
            'id': p.id,
            'name': p.name,
            'position': p.position
        } for p in players]
    })

@unlimited.route('/add_event', methods=['POST'])
@login_required
def add_event():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    try:
        data = request.get_json()
        player_id = data.get('player_id')
        event_type = data.get('event_type')
        match_info = data.get('match_info')
        
        # Define points for different event types
        points_map = {
            'goal': 3,
            'assist': 2,
            'clean_sheet': 2,
            'yellow_card': -1,
            'red_card': -3,
            'own_goal': -2
        }
        
        points = points_map.get(event_type, 0)
        
        event = UnlimitedMatchEvent(
            player_id=player_id,
            event_type=event_type,
            points=points,
            match_info=match_info,
            created_by=current_user.id
        )
        
        # Update team points
        teams_with_player = UnlimitedTeam.query.join(UnlimitedTeamPlayer)\
            .filter(UnlimitedTeamPlayer.player_id == player_id)\
            .all()
            
        for team in teams_with_player:
            team.points += points
        
        db.session.add(event)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Event added successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@unlimited.route('/delete_event/<int:event_id>', methods=['DELETE'])
@login_required
def delete_event(event_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    try:
        event = UnlimitedMatchEvent.query.get_or_404(event_id)
        
        # Reverse points effect
        teams_with_player = UnlimitedTeam.query.join(UnlimitedTeamPlayer)\
            .filter(UnlimitedTeamPlayer.player_id == event.player_id)\
            .all()
            
        for team in teams_with_player:
            team.points -= event.points
        
        db.session.delete(event)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Event deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@unlimited.route('/get_events')
@login_required
def get_events():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    events = UnlimitedMatchEvent.query.order_by(UnlimitedMatchEvent.created_at.desc()).all()
    events_data = []
    
    for event in events:
        player = UnlimitedPlayer.query.get(event.player_id)
        events_data.append({
            'id': event.id,
            'player': {
                'name': player.name
            },
            'event_type': event.event_type,
            'points': event.points,
            'match_info': event.match_info,
            'created_at': event.created_at.isoformat()
        })
    
    return jsonify({'success': True, 'events': events_data})

@unlimited.route('/delete_player/<int:player_id>', methods=['POST'])
@login_required
def delete_player(player_id):
    """Delete a player and their image"""
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'غير مصرح بالوصول'}), 403

    try:
        player = UnlimitedPlayer.query.get_or_404(player_id)
        
        # حذف الصورة إذا كانت موجودة
        if player.image_url:
            image_path = os.path.join(app.root_path, 'static', player.image_url.lstrip('/'))
            if os.path.exists(image_path):
                os.remove(image_path)
        
        db.session.delete(player)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'تم حذف اللاعب بنجاح'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'حدث خطأ أثناء حذف اللاعب: {str(e)}'}), 400

@unlimited.route('/release_player/<int:player_id>', methods=['POST'])
@login_required
def release_player(player_id):
    """Release a player from the team"""
    try:
        # Get user's team
        team = UnlimitedTeam.query.filter_by(user_id=current_user.id).first()
        if not team:
            return jsonify({'success': False, 'message': 'الفريق غير موجود'}), 404

        # Find the player in the team
        team_player = UnlimitedTeamPlayer.query.filter_by(
            team_id=team.id,
            player_id=player_id
        ).first()

        if not team_player:
            return jsonify({'success': False, 'message': 'اللاعب غير موجود في فريقك'}), 404

        # Save player details for the response
        player = UnlimitedPlayer.query.get(player_id)
        player_name = player.name if player else 'اللاعب'

        # Remove the player from the team
        db.session.delete(team_player)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'تم التخلي عن {player_name} بنجاح'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'حدث خطأ أثناء التخلي عن اللاعب: {str(e)}'
        }), 400
