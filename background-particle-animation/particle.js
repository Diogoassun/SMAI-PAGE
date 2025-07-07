document.addEventListener('DOMContentLoaded', () => {
const container = document.querySelector('.particles-container');
const particleCount = 50; // Quantidade de partículas

    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.classList.add('particle');
        
        particle.style.top = `${Math.random() * 100}%`;
        particle.style.left = `${Math.random() * 100}%`;
        particle.style.animationDelay = `${Math.random() * -20}s`;
        particle.style.animationDuration = `${15 + Math.random() * 10}s`;
        
        container.appendChild(particle);
    }
});