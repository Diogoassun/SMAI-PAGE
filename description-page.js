// --- Elementos do DOM ---
const scrollContainer = document.getElementById("func-scroll");
const pageDisplay = document.getElementById("pageDisplay");
const prevButton = document.getElementById("prevBtn");
const nextButton = document.getElementById("nextBtn");

// --- Estado do Carrossel ---
let originalItems = [];
let totalPages = 0;
let currentPageIndex = 0;
let pageObserver; // Variável para guardar nosso Intersection Observer

/**
 * 1. FUNÇÃO PRINCIPAL DE CONFIGURAÇÃO
 */
function setupCarousel() {
    if (originalItems.length === 0) {
        originalItems = Array.from(scrollContainer.querySelectorAll(".description"));
    }
    
    scrollContainer.innerHTML = '';
    originalItems.forEach(item => scrollContainer.appendChild(item));
    
    if (!originalItems.length) return;

    const itemsPerPage = calculateItemsPerPage();
    groupItemsIntoPages(itemsPerPage);

    // Após criar as páginas, configura o observer para assisti-las
    setupIntersectionObserver();
}

/**
 * 2. O MOTOR DE AGRUPAMENTO
 */
function groupItemsIntoPages(itemsPerPage) {
    const allItems = Array.from(scrollContainer.children);
    scrollContainer.innerHTML = '';

    totalPages = Math.ceil(allItems.length / itemsPerPage);

    for (let i = 0; i < allItems.length; i += itemsPerPage) {
        const pageWrapper = document.createElement('div');
        pageWrapper.className = 'description-page';
        
        // Adiciona um atributo para sabermos o índice da página facilmente
        pageWrapper.dataset.pageIndex = i / itemsPerPage;

        const itemsForPage = allItems.slice(i, i + itemsPerPage);
        itemsForPage.forEach(item => pageWrapper.appendChild(item));
        
        scrollContainer.appendChild(pageWrapper);
    }
}

/**
 * 3. CONFIGURA O INTERSECTION OBSERVER
 * O "olho" que assiste as páginas e atualiza o contador.
 */
function setupIntersectionObserver() {
    // Limpa qualquer observer antigo antes de criar um novo
    if (pageObserver) pageObserver.disconnect();

    const options = {
      root: scrollContainer, // O container de rolagem é a área de observação
      rootMargin: '0px',
      threshold: 0.51 // Ativa quando mais de 51% da página está visível
    };

    pageObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            // Se uma página está visível (passou do threshold)
            if (entry.isIntersecting) {
                // Pega o índice que guardamos no atributo 'data-page-index'
                const newIndex = parseInt(entry.target.dataset.pageIndex);
                currentPageIndex = newIndex;
                updatePageDisplay();
            }
        });
    }, options);

    // Manda o observer assistir cada uma das páginas
    const pages = scrollContainer.querySelectorAll('.description-page');
    pages.forEach(page => pageObserver.observe(page));
}


/**
 * 4. NAVEGAÇÃO E ATUALIZAÇÃO
 */
function updatePageDisplay() {
    pageDisplay.textContent = `${currentPageIndex + 1}/${totalPages}`;
}

function navigate(direction) {
    const newIndex = currentPageIndex + direction;
    const pages = scrollContainer.querySelectorAll('.description-page');

    if (newIndex >= 0 && newIndex < pages.length) {
        pages[newIndex].scrollIntoView({
            behavior: 'smooth',
            inline: 'center',
            block: 'nearest'
        });
    }
}

function calculateItemsPerPage() {
    const styles = window.getComputedStyle(scrollContainer);
    const gap = parseFloat(styles.gap) || 16;
    const itemWidth = originalItems[0].offsetWidth;
    const containerWidth = scrollContainer.clientWidth;
    const itemsPerPage = Math.floor((containerWidth + gap) / (itemWidth + gap));
    return itemsPerPage > 0 ? itemsPerPage : 1;
}


// --- Event Listeners ---
prevButton.addEventListener('click', () => navigate(-1));
nextButton.addEventListener('click', () => navigate(1));

window.addEventListener('load', setupCarousel);
window.addEventListener('resize', setupCarousel);