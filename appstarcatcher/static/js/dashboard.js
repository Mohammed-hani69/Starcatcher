document.addEventListener('DOMContentLoaded', function() {
    // العناصر الرئيسية
    const elements = {
        createPackBtn: document.querySelector('.add_pack'),
        packModal: document.getElementById('packModal'),
        packModalOverlay: document.getElementById('packModalOverlay'),
        closePackModal: document.getElementById('closePackModal'),
        cancelPackBtn: document.getElementById('cancelPackBtn'),
        savePackBtn: document.getElementById('savePackBtn'),
        newPackForm: document.getElementById('newPackForm'),
        imageInput: document.getElementById('imageInput'),
        previewContainer: document.querySelector('.preview-container'),
        previewImage: document.querySelector('.preview-image'),
        removeImageBtn: document.querySelector('.remove-image')
    };

    // معالجة النافذة المنبثقة
    function openModal() {
        elements.packModal.classList.add('active');
        elements.packModalOverlay.classList.add('active');
    }

    function closeModal() {
        elements.packModal.classList.remove('active');
        elements.packModalOverlay.classList.remove('active');
        elements.newPackForm.reset();
        elements.previewContainer.style.display = 'none';
    }

    // معالجة الصور
    function handleImagePreview(file) {
        if (file) {
            const reader = new FileReader();
            reader.onload = function(e) {
                elements.previewImage.src = e.target.result;
                elements.previewContainer.style.display = 'block';
            }
            reader.readAsDataURL(file);
        }
    }

    function removeImage(e) {
        e.stopPropagation();
        elements.imageInput.value = '';
        elements.previewContainer.style.display = 'none';
        elements.previewImage.src = '';
    }

    // حفظ البيانات
    async function savePack(e) {
        e.preventDefault();
        
        const formData = new FormData(elements.newPackForm);
        
        // إضافة الصورة
        if (elements.imageInput.files[0]) {
            formData.append('image', elements.imageInput.files[0]);
        }
    
        // إضافة نسب النادرية كـ JSON
        const rarityOdds = {
            common: parseInt(formData.get('rarity_common')),
            rare: parseInt(formData.get('rarity_rare')),
            epic: parseInt(formData.get('rarity_epic')),
            legendary: parseInt(formData.get('rarity_legendary'))
        };
        formData.append('rarity_odds', JSON.stringify(rarityOdds));
    
        // تأكد من أن CSRF Token موجود في FormData
        const csrfToken = document.querySelector('input[name="csrf_token"]').value;
        formData.append('csrf_token', csrfToken);
    
        try {
            const response = await fetch('/packs', {
                method: 'POST',
                body: formData
            });
    
            const text = await response.text();
            console.log(text);
    
            try {
                const data = JSON.parse(text);
                if (response.ok) {
                    alert(data.message);
                    closeModal();
                    if (typeof refreshPacksList === 'function') {
                        refreshPacksList();
                    }
                } else {
                    alert(data.message || 'حدث خطأ أثناء حفظ الباكج');
                }
            } catch (error) {
                console.error('Failed to parse response as JSON:', text);
                alert('حدث خطأ غير متوقع من الخادم');
            }
        } catch (error) {
            alert('حدث خطأ أثناء حفظ الباكج');
            console.error(error);
        }
    }

    // إضافة المستمعين
    elements.createPackBtn.addEventListener('click', openModal);
    elements.closePackModal.addEventListener('click', closeModal);
    elements.cancelPackBtn.addEventListener('click', closeModal);
    elements.packModalOverlay.addEventListener('click', closeModal);
    elements.savePackBtn.addEventListener('click', savePack);
    elements.imageInput.addEventListener('change', (e) => handleImagePreview(e.target.files[0]));
    elements.removeImageBtn.addEventListener('click', removeImage);
});





//حذف الباكج 
document.addEventListener('DOMContentLoaded', function() {
    // البحث عن جميع أزرار الحذف
    document.querySelectorAll('.delete_pack').forEach(button => {
        button.addEventListener('click', async function() {
            const packId = this.getAttribute('data-pack-id');
            const packCard = this.closest('.player-card');  // تحديد العنصر الخاص بالباكج
            
            if (confirm('هل أنت متأكد أنك تريد حذف هذا الباكج؟')) {
                try {
                    // إضافة تأثير الحذف (إضافة الكلاس الخاص بالتأثير)
                    packCard.classList.add('deleting');
                    
                    // تعطيل الأزرار أثناء الحذف
                    const buttons = packCard.querySelectorAll('.action-btn');
                    buttons.forEach(btn => btn.disabled = true);

                    // الحصول على CSRF token من meta tag
                    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

                    // إرسال طلب الحذف باستخدام fetch
                    const response = await fetch(`/packs/${packId}`, {
                        method: 'DELETE', // تحديد أنه طلب حذف
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': csrfToken  // إضافة CSRF token إلى الهيدر
                        }
                    });

                    const data = await response.json();

                    if (response.ok) {
                        // الانتظار حتى يكتمل تأثير الحذف قبل إزالة العنصر
                        setTimeout(() => {
                            packCard.remove();
                        }, 500);  // الوقت المتاح لتأثير الحذف

                        // إظهار رسالة نجاح بعد الحذف
                        const notification = document.createElement('div');
                        notification.textContent = "تم الحذف بنجاح!";
                        notification.style.position = 'fixed';
                        notification.style.top = '20px';
                        notification.style.right = '20px';
                        notification.style.backgroundColor = '#4CAF50';
                        notification.style.color = 'white';
                        notification.style.padding = '15px';
                        notification.style.borderRadius = '5px';
                        notification.style.zIndex = '1000';

                        document.body.appendChild(notification);

                        setTimeout(() => {
                            notification.remove();
                        }, 3000);  // إخفاء الإشعار بعد 3 ثوانٍ
                    } else {
                        alert(data.message); // رسالة فشل
                        packCard.classList.remove('deleting');
                        buttons.forEach(btn => btn.disabled = false);
                    }
                } catch (error) {
                    console.error('Error:', error);
                    alert('حدث خطأ أثناء الحذف');
                    packCard.classList.remove('deleting');
                    const buttons = packCard.querySelectorAll('.action-btn');
                    buttons.forEach(btn => btn.disabled = false);
                }
            }
        });
    });
});








document.addEventListener('DOMContentLoaded', function() {
    // تعريف العناصر
    const elements = {
        createListingBtn: document.querySelector('.add_player'),
        modal: document.getElementById('listingModal'),
        overlay: document.getElementById('listingModalOverlay'),
        closeBtn: document.getElementById('closeListingModal'),
        cancelBtn: document.getElementById('cancelListingBtn'),
        saveBtn: document.getElementById('saveListingBtn'),
        form: document.getElementById('newListingForm'),
        playerSelect: document.getElementById('playerSelect'),
        priceInput: document.getElementById('price'),
        expiresInput: document.getElementById('expires_at'),
        statusSelect: document.getElementById('status')
    };

    // التحقق من وجود جميع العناصر
    for (const [key, element] of Object.entries(elements)) {
        if (!element) {
            console.error(`العنصر ${key} غير موجود في الصفحة`);
            return;
        }
    }

    // الحصول على CSRF token
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
    if (!csrfToken) {
        console.error("CSRF token غير موجود في الصفحة");
        return;
    }

    // تحميل قائمة اللاعبين
    // تعديل دالة loadPlayers
    async function loadPlayers() {
        try {
            console.log('بدء تحميل اللاعبين...');
            const response = await fetch('/get_players', {
                headers: {
                    'X-CSRFToken': csrfToken,
                    'Accept': 'application/json'
                }
            });

            console.log('استجابة الخادم:', response.status);
            const data = await response.json();
            console.log('البيانات المستلمة:', data);

            if (!response.ok) {
                throw new Error(`فشل تحميل اللاعبين: ${response.status} - ${data.error || 'خطأ غير معروف'}`);
            }

            // باقي الكود...
        } catch (error) {
            console.error('تفاصيل الخطأ الكاملة:', error);
            showError('فشل في تحميل قائمة اللاعبين');
        }
    }
    // التحقق من صحة البيانات
    function validateForm() {
        const errors = [];
        
        if (!elements.playerSelect.value) {
            errors.push('يرجى اختيار لاعب');
        }
        
        const price = parseInt(elements.priceInput.value);
        if (isNaN(price) || price <= 0) {
            errors.push('يرجى إدخال سعر صحيح');
        }
        
        if (!elements.expiresInput.value) {
            errors.push('يرجى تحديد تاريخ الانتهاء');
        }
        
        if (!elements.statusSelect.value) {
            errors.push('يرجى اختيار الحالة');
        }
        
        return errors;
    }

    // عرض رسالة خطأ
    function showError(message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'alert alert-danger';
        errorDiv.textContent = message;
        elements.form.insertBefore(errorDiv, elements.form.firstChild);
        
        setTimeout(() => errorDiv.remove(), 5000);
    }

    // إدارة النافذة المنبثقة
    function toggleModal(show = true) {
        const action = show ? 'add' : 'remove';
        elements.modal.classList[action]('active');
        elements.overlay.classList[action]('active');
        
        if (show) {
            loadPlayers();
            elements.form.reset();
        }
    }

    // معالجة الإرسال
    async function handleSubmit(e) {
        e.preventDefault();
        
        const errors = validateForm();
        if (errors.length > 0) {
            showError(errors.join('\n'));
            return;
        }
        
        try {
            const listingData = {
                player_id: parseInt(elements.playerSelect.value), // استخدام القيمة من select
                price: parseInt(elements.priceInput.value), // استخدام القيمة من input
                expires_at: elements.expiresInput.value, // استخدام القيمة من input
                status: elements.statusSelect.value // استخدام القيمة من select
            };
            
            const response = await fetch('/add_listing', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify(listingData)
            });

            const data = await response.json();
            
            if (response.ok) {
                toggleModal(false);
                location.href = '/';  // إعادة التوجيه بعد النجاح
            } else {
                showError(data.message || 'حدث خطأ أثناء حفظ البيانات');
            }
        } catch (error) {
            console.error('خطأ في حفظ البيانات:', error);
            showError('حدث خطأ أثناء الاتصال بالخادم');
        }
    }

    // إضافة مستمعي الأحداث
    elements.createListingBtn.addEventListener('click', () => toggleModal(true));
    elements.closeBtn.addEventListener('click', () => toggleModal(false));
    elements.cancelBtn.addEventListener('click', () => toggleModal(false));
    elements.overlay.addEventListener('click', () => toggleModal(false));
    elements.form.addEventListener('submit', handleSubmit);

    // منع إغلاق النافذة عند النقر داخلها
    elements.modal.addEventListener('click', (e) => e.stopPropagation());
});



