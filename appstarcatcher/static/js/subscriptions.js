document.addEventListener('DOMContentLoaded', function() {
    // Load subscriptions from API and display them dynamically
    fetchSubscriptions();
    
    // Add event listeners to subscription buttons
    const standardBtn = document.querySelector('.standard-btn');
    const premiumBtn = document.querySelector('.premium-btn');
    
    if (standardBtn) {
        standardBtn.addEventListener('click', function() {
            purchaseSubscription(1); // Assuming standard package has ID 1
        });
    }
    
    if (premiumBtn) {
        premiumBtn.addEventListener('click', function() {
            purchaseSubscription(2); // Assuming premium package has ID 2
        });
    }
});

// Function to fetch subscriptions from the API
function fetchSubscriptions() {
    fetch('/api/subscriptions')
        .then(response => response.json())
        .then(data => {
            // You can use this data to dynamically update your package information
            console.log('Available subscriptions:', data);
            
            // Optional: Update subscription card details dynamically
            updateSubscriptionCards(data);
        })
        .catch(error => {
            console.error('Error fetching subscriptions:', error);
        });
}

// Function to update subscription card details
function updateSubscriptionCards(subscriptions) {
    // Find standard and premium packages in the returned data
    const standardPackage = subscriptions.find(sub => sub.package_type === 'standard');
    const premiumPackage = subscriptions.find(sub => sub.package_type === 'premium');
    
    // Update standard package details if found
    if (standardPackage) {
        const standardCard = document.querySelector('.standard-card');
        if (standardCard) {
            // Update price
            const priceElement = document.createElement('p');
            priceElement.className = 'package-price';
            priceElement.textContent = `${standardPackage.price} ${standardPackage.is_outside_egypt ? 'دولار' : 'جنيه'}`;
            
            // Update features if they come from the API
            const featureList = standardCard.querySelector('.feature-list');
            if (featureList && standardPackage.package_details) {
                // Assuming package_details is a JSON string of features
                try {
                    const features = JSON.parse(standardPackage.package_details);
                    featureList.innerHTML = '';
                    features.forEach(feature => {
                        const li = document.createElement('li');
                        li.textContent = feature;
                        featureList.appendChild(li);
                    });
                } catch (e) {
                    console.error('Error parsing standard package details:', e);
                }
            }
            
            // Add price before the button
            const button = standardCard.querySelector('.subscription-btn');
            if (button && !standardCard.querySelector('.package-price')) {
                button.parentNode.insertBefore(priceElement, button);
            }
            
            // Update button with subscription ID
            const standardBtn = standardCard.querySelector('.standard-btn');
            if (standardBtn) {
                standardBtn.setAttribute('data-subscription-id', standardPackage.id);
            }
        }
    }
    
    // Update premium package details if found
    if (premiumPackage) {
        const premiumCard = document.querySelector('.premium-card');
        if (premiumCard) {
            // Update price
            const priceElement = document.createElement('p');
            priceElement.className = 'package-price';
            priceElement.textContent = `${premiumPackage.price} ${premiumPackage.is_outside_egypt ? 'دولار' : 'جنيه'}`;
            
            // Update features if they come from the API
            const featureList = premiumCard.querySelector('.feature-list');
            if (featureList && premiumPackage.package_details) {
                try {
                    const features = JSON.parse(premiumPackage.package_details);
                    featureList.innerHTML = '';
                    features.forEach(feature => {
                        const li = document.createElement('li');
                        li.textContent = feature;
                        featureList.appendChild(li);
                    });
                } catch (e) {
                    console.error('Error parsing premium package details:', e);
                }
            }
            
            // Add price before the button
            const button = premiumCard.querySelector('.subscription-btn');
            if (button && !premiumCard.querySelector('.package-price')) {
                button.parentNode.insertBefore(priceElement, button);
            }
            
            // Update button with subscription ID
            const premiumBtn = premiumCard.querySelector('.premium-btn');
            if (premiumBtn) {
                premiumBtn.setAttribute('data-subscription-id', premiumPackage.id);
            }
        }
    }
}

// Function to purchase a subscription
function purchaseSubscription(subscriptionId) {
    // Get user ID (you'll need to implement this according to your auth system)
    const userId = getCurrentUserId();
    
    if (!userId) {
        // Handle not logged in case
        alert('يرجى تسجيل الدخول أولاً');
        // Optional: Redirect to login page
        window.location.href = '/login';
        return;
    }
    
    // Prepare data for API call
    const data = {
        user_id: userId,
        subscription_id: subscriptionId
    };
    
    // Call purchase subscription API
    fetch('/api/purchase_subscription', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(result => {
        if (result.success) {
            alert('تم الاشتراك بنجاح!');
            // Refresh page or update UI
            window.location.reload();
        } else {
            alert(`فشل الاشتراك: ${result.message}`);
        }
    })
    .catch(error => {
        console.error('Error purchasing subscription:', error);
        alert('حدث خطأ أثناء محاولة الاشتراك');
    });
}

// Function to get current user ID - implement this based on your authentication system
function getCurrentUserId() {
    // This is a placeholder - implement according to your auth system
    // Examples:
    // - You might have the user ID in localStorage
    // - You might have it in a cookie
    // - You might need to fetch it from another API endpoint
    
    // For example:
    return localStorage.getItem('userId') || sessionStorage.getItem('userId');
    
    // Or if you're using JWT:
    // const token = localStorage.getItem('token');
    // if (token) {
    //     const payload = JSON.parse(atob(token.split('.')[1]));
    //     return payload.user_id;
    // }
    // return null;
}