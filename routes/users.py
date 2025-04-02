from sqlalchemy import func
from appstarcatcher.models import UserClub, UserSubscriptionPurchases
from appstarcatcher.models import Users, UserSubscriptionPurchases
from appstarcatcher import db

# ...existing code...

# Update the query to use proper grouping
users_query = (
    db.session.query(
        Users,
        func.count(UserClub.id).label('player_count'),
        func.dense_rank().over(order_by=func.count(UserClub.id).desc()).label('rank'),
        func.max(UserSubscriptionPurchases.id).label('user_subscription_purchases_id'),
        func.max(UserSubscriptionPurchases.user_id).label('user_subscription_purchases_user_id'),
        func.max(UserSubscriptionPurchases.subscription_id).label('user_subscription_purchases_subscription_id'),
        func.max(UserSubscriptionPurchases.payment_method).label('user_subscription_purchases_payment_method'),
        func.max(UserSubscriptionPurchases.price).label('user_subscription_purchases_price'),
        func.max(UserSubscriptionPurchases.username).label('user_subscription_purchases_username'),
        func.max(UserSubscriptionPurchases.email).label('user_subscription_purchases_email'),
        func.max(UserSubscriptionPurchases.country).label('user_subscription_purchases_country'),
        func.max(UserSubscriptionPurchases.status).label('user_subscription_purchases_status'),
        func.max(UserSubscriptionPurchases.purchase_date).label('user_subscription_purchases_purchase_date'),
        func.max(UserSubscriptionPurchases.expiry_date).label('user_subscription_purchases_expiry_date')
    )
    .outerjoin(UserClub, Users.id == UserClub.user_id)
    .outerjoin(
        UserSubscriptionPurchases,
        db.and_(
            Users.id == UserSubscriptionPurchases.user_id,
            UserSubscriptionPurchases.status == 'active'
        )
    )
    .group_by(Users.id)
)

# ...existing code...
