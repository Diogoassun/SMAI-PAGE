// --- Elementos do DOM ---
const scrollContainer = document.getElementById("func-scroll");
const pageDisplay = document.getElementById("pageDisplay");
const prevButton = document.getElementById("prevBtn");
const nextButton = document.getElementById("nextBtn");

// --- Estado do Carrossel ---
let config = {
    totalPages: 0,
    pageWidth: 0,
    containerWidth: 0,
    gap: 16,
};

// --- Controle de Animação e Toque ---
let isAnimating = false; // Impede novas ações durante uma animação
let touchStartX = 0;
const swipeThreshold = 50; // Mínimo de pixels para considerar um swipe

/**
 * 1. CONFIGURA O LAYOUT
 * Roda no início e no redimensionamento da tela.
 */
function setupLayout() {
    const items = Array.from(scrollContainer.querySelectorAll(".description"));
    if (!items.length) return;

    config.gap = parseFloat(window.getComputedStyle(scrollContainer).gap) || 16;
    const itemWidth = items[0].offsetWidth;
    config.containerWidth = scrollContainer.clientWidth;
    
    const itemsPerPage = Math.floor((config.containerWidth + config.gap) / (itemWidth + config.gap));
    config.pageWidth = (itemsPerPage * itemWidth) + ((itemsPerPage - 1) * config.gap);
    config.totalPages = Math.ceil(items.length / itemsPerPage);

    // Alinha a página atual sem animação ao reconfigurar
    goToPage(getCurrentPageIndex(), false);
}

/**
 * 2. FUNÇÃO CENTRAL DE MOVIMENTO
 * Leva o carrossel para uma página específica.
 */
function goToPage(pageIndex, animated = true) {
    // Trava para não aceitar novas ações enquanto a animação ocorre
    isAnimating = true;

    const targetScrollLeft = getTargetScrollLeft(pageIndex);
    updatePageDisplay(pageIndex);

    scrollContainer.scrollTo({
        left: targetScrollLeft,
        behavior: animated ? 'smooth' : 'auto',
    });

    // Libera a trava após a animação terminar
    setTimeout(() => {
        isAnimating = false;
    }, 400); // Duração segura para a animação 'smooth'
}

/**
 * 3. LÓGICA DE NAVEGAÇÃO
 * Calcula a próxima página e chama a função de movimento.
 */
function changePage(direction) {
    if (isAnimating) return; // Ignora se já estiver animando

    const currentIndex = getCurrentPageIndex();
    let nextIndex = currentIndex + direction;

    // Garante que o índice não saia dos limites (0 a totalPages-1)
    nextIndex = Math.max(0, Math.min(nextIndex, config.totalPages - 1));

    // Só move se a página for diferente da atual
    if (nextIndex !== currentIndex) {
        goToPage(nextIndex);
    }
}

// --- Funções Auxiliares ---
function getCurrentPageIndex() {
    if (!config.pageWidth) return 0;
    return Math.round(scrollContainer.scrollLeft / config.pageWidth);
}

function getTargetScrollLeft(pageIndex) {
    const pageStart = pageIndex * config.pageWidth;
    const pageCenter = pageStart + (config.pageWidth / 2);
    const containerCenter = config.containerWidth / 2;
    return pageCenter - containerCenter;
}

function updatePageDisplay(pageIndex) {
    pageDisplay.textContent = `${pageIndex + 1}/${config.totalPages}`;
}


// --- Event Listeners de Alta Fidelidade ---

// Listener para Roda do Mouse e Trackpad
scrollContainer.addEventListener('wheel', (e) => {
    // Impede a rolagem padrão do navegador para nós assumirmos o controle
    e.preventDefault();
    if (isAnimating) return;

    const direction = Math.sign(e.deltaX);
    if (direction !== 0) {
        changePage(direction);
    }
});

// Listeners para Toque (Mobile)
scrollContainer.addEventListener('touchstart', (e) => {
    if (isAnimating) return;
    touchStartX = e.touches[0].clientX;
});

scrollContainer.addEventListener('touchend', (e) => {
    if (isAnimating) return;
    const touchEndX = e.changedTouches[0].clientX;
    const deltaX = touchEndX - touchStartX;

    if (Math.abs(deltaX) > swipeThreshold) {
        const direction = deltaX < 0 ? 1 : -1;
        changePage(direction);
    }
});

// Listener para os botões (mantém a funcionalidade)
prevButton.addEventListener('click', () => changePage(-1));
nextButton.addEventListener('click', () => changePage(1));

// Listeners para reponsividade
window.addEventListener('load', setupLayout);
window.addEventListener('resize', setupLayout);