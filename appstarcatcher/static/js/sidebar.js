document.addEventListener('DOMContentLoaded', function() {
    const burgerMenu = document.querySelector('.burger-menu');
    const sidebar = document.querySelector('.sidebar');
    const overlay = document.querySelector('.sidebar-overlay');

    function toggleSidebar() {
        burgerMenu?.classList.toggle('active');
        sidebar?.classList.toggle('active');
        overlay?.classList.toggle('active');
        
        if (sidebar?.classList.contains('active')) {
            document.body.style.overflow = 'hidden';
            overlay.style.display = 'block';
        } else {
            document.body.style.overflow = '';
            overlay.style.display = 'none';
        }
    }

    // تفعيل زر القائمة
    burgerMenu?.addEventListener('click', function(e) {
        e.preventDefault();
        toggleSidebar();
    });

    // إغلاق السايدبار عند النقر على الخلفية
    overlay?.addEventListener('click', toggleSidebar);

    // إغلاق السايدبار عند تغيير حجم النافذة
    window.addEventListener('resize', () => {
        if (window.innerWidth > 992 && sidebar?.classList.contains('active')) {
            toggleSidebar();
        }
    });

    // معالجة الصور
    document.querySelectorAll('.player-image').forEach(img => {
        img.addEventListener('load', function() {
            this.classList.add('loaded');
        });
        
        img.addEventListener('error', function() {
            this.src = 'static/image/STAR CATCHER FINAL LOGO-11.png';
        });
    });
});
