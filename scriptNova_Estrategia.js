// --- Elementos do DOM ---
const scrollContainer = document.getElementById("func-scroll");
const pageDisplay = document.getElementById("pageDisplay");
const prevButton = document.getElementById("prevBtn");
const nextButton = document.getElementById("nextBtn");

// --- Estado do Carrossel ---
let originalItems = []; // Guarda os itens originais para o redimensionamento
let totalPages = 0;
let currentPageIndex = 0;

/**
 * 1. FUNÇÃO PRINCIPAL DE CONFIGURAÇÃO
 * Orquestra o agrupamento e a configuração inicial.
 */
function setupCarousel() {
    // Guarda os itens originais na primeira execução
    if (originalItems.length === 0) {
        originalItems = Array.from(scrollContainer.querySelectorAll(".description"));
    }
    
    // Restaura o container ao seu estado original antes de reagrupar
    scrollContainer.innerHTML = '';
    originalItems.forEach(item => scrollContainer.appendChild(item));
    
    if (!originalItems.length) return;

    // Calcula quantos itens cabem por página
    const styles = window.getComputedStyle(scrollContainer);
    const gap = parseFloat(styles.gap) || 16;
    const itemWidth = originalItems[0].offsetWidth;
    const containerWidth = scrollContainer.clientWidth;
    const itemsPerPage = Math.floor((containerWidth + gap) / (itemWidth + gap));
    
    // Agrupa os itens em divs de página
    groupItemsIntoPages(itemsPerPage > 0 ? itemsPerPage : 1);

    // Atualiza o display
    updatePageDisplay();
}

/**
 * 2. O MOTOR DE AGRUPAMENTO
 * Pega os itens e os coloca dentro de wrappers de página.
 */
function groupItemsIntoPages(itemsPerPage) {
    const allItems = Array.from(scrollContainer.children);
    scrollContainer.innerHTML = ''; // Limpa o container para receber as páginas

    totalPages = Math.ceil(allItems.length / itemsPerPage);

    for (let i = 0; i < allItems.length; i += itemsPerPage) {
        const pageWrapper = document.createElement('div');
        pageWrapper.className = 'description-page';
        
        const itemsForPage = allItems.slice(i, i + itemsPerPage);
        itemsForPage.forEach(item => pageWrapper.appendChild(item));
        
        scrollContainer.appendChild(pageWrapper);
    }
}

/**
 * 3. NAVEGAÇÃO E ATUALIZAÇÃO
 * Funções simplificadas que agora lidam com elementos de página reais.
 */
function updatePageDisplay() {
    // Calcula a página atual baseando-se na posição do scroll
    const pages = scrollContainer.querySelectorAll('.description-page');
    if (pages.length === 0) return;
    
    const pageWidth = pages[0].offsetWidth;
    currentPageIndex = Math.round(scrollContainer.scrollLeft / pageWidth);
    
    pageDisplay.textContent = `${currentPageIndex + 1}/${totalPages}`;
}

function navigate(direction) {
    const newIndex = currentPageIndex + direction;
    const pages = scrollContainer.querySelectorAll('.description-page');

    // Garante que o índice esteja dentro dos limites
    if (newIndex >= 0 && newIndex < pages.length) {
        const targetPage = pages[newIndex];
        // O método nativo do navegador para rolar um elemento para a vista!
        targetPage.scrollIntoView({
            behavior: 'smooth',
            inline: 'center',
            block: 'nearest'
        });
    }
}


// --- Event Listeners ---
// O listener de scroll agora é muito simples: só atualiza o texto.
// A animação e o "snap" são 100% controlados pelo CSS.
scrollContainer.addEventListener('scroll', () => {
    // Usa um timeout para atualizar o display apenas quando a rolagem para.
    clearTimeout(scrollContainer.scrollTimeout);
    scrollContainer.scrollTimeout = setTimeout(updatePageDisplay, 100);
});

// Botões agora chamam a navegação simples
prevButton.addEventListener('click', () => navigate(-1));
nextButton.addEventListener('click', () => navigate(1));

// Reconfigura tudo no load e no resize para garantir a responsividade
window.addEventListener('load', setupCarousel);
window.addEventListener('resize', setupCarousel);