// Mobile menu toggle
const menuBtn = document.querySelector('.mobile-menu-btn');
const mobileMenu = document.querySelector('.mobile-menu');

menuBtn.addEventListener('click', () => {
    mobileMenu.classList.toggle('open');
    menuBtn.classList.toggle('active');
});

// Close mobile menu on link click
document.querySelectorAll('.mobile-menu a').forEach(link => {
    link.addEventListener('click', () => {
        mobileMenu.classList.remove('open');
        menuBtn.classList.remove('active');
    });
});

// Smooth scroll for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    });
});

// Nav background on scroll
const nav = document.querySelector('.nav');
window.addEventListener('scroll', () => {
    if (window.scrollY > 20) {
        nav.style.borderBottomColor = 'rgba(30, 30, 46, 0.8)';
    } else {
        nav.style.borderBottomColor = 'rgba(30, 30, 46, 0.3)';
    }
});

// Intersection Observer for fade-in animations
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('visible');
            observer.unobserve(entry.target);
        }
    });
}, observerOptions);

// Add animation class to elements
document.querySelectorAll('.feature-card, .agent-card, .step, .security-item, .download-card, .showcase-item').forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(20px)';
    el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
    observer.observe(el);
});

// Add visible styles
const style = document.createElement('style');
style.textContent = '.visible { opacity: 1 !important; transform: translateY(0) !important; }';
document.head.appendChild(style);

// Stagger animations for grid items
document.querySelectorAll('.features-grid, .agents-grid, .security-grid, .download-cards').forEach(grid => {
    const items = grid.children;
    Array.from(items).forEach((item, i) => {
        item.style.transitionDelay = `${i * 0.1}s`;
    });
});

// Terminal typing animation
const typingEl = document.querySelector('.typing');
if (typingEl) {
    const text = typingEl.textContent;
    typingEl.textContent = '';
    let i = 0;

    const typeObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const typeChar = () => {
                    if (i < text.length) {
                        typingEl.textContent += text.charAt(i);
                        i++;
                        setTimeout(typeChar, 30 + Math.random() * 40);
                    }
                };
                setTimeout(typeChar, 800);
                typeObserver.unobserve(entry.target);
            }
        });
    }, { threshold: 0.5 });

    typeObserver.observe(document.querySelector('.terminal-mockup'));
}
