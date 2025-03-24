from flask import current_app
from flask_migrate import Migrate
from appstarcatcher import db

def upgrade():
    # إضافة العمود الجديد
    db.engine.execute('ALTER TABLE user ADD COLUMN new_member_reward_collected BOOLEAN DEFAULT FALSE')

def downgrade():
    # إزالة العمود في حالة التراجع
    db.engine.execute('ALTER TABLE user DROP COLUMN new_member_reward_collected')
