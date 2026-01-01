// Smooth scroll for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        document.querySelector(this.getAttribute('href')).scrollIntoView({
            behavior: 'smooth'
        });
    });
});

// Simple Console Effect in Hero
const badge = document.querySelector('.badge');
if(badge) {
    badge.addEventListener('click', () => {
        badge.textContent = "Copied npm install onion-ai!";
        navigator.clipboard.writeText('npm install onion-ai');
        setTimeout(() => {
            badge.textContent = "v1.0.0 Now Available";
        }, 2000);
    });
}
