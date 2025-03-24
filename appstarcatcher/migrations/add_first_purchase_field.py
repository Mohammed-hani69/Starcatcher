from flask import current_app
from flask_migrate import Migrate
from appstarcatcher import db

def upgrade():
    # إضافة العمود الجديد
    db.engine.execute('ALTER TABLE users ADD COLUMN first_purchase_reward_collected BOOLEAN DEFAULT FALSE')

def downgrade():
    # إزالة العمود في حالة التراجع
    db.engine.execute('ALTER TABLE users DROP COLUMN first_purchase_reward_collected')
