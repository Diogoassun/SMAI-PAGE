// --- Elementos do DOM ---
const scrollContainer = document.getElementById("func-scroll");
const pageDisplay = document.getElementById("pageDisplay");
const prevButton = document.getElementById("prevBtn");
const nextButton = document.getElementById("nextBtn");

// --- Variáveis de Estado ---
let layoutConfig = {
    itemsPerPage: 0,
    totalPages: 0,
    gap: 0,
    pageWidth: 0,
};
let scrollTimeout;

/**
 * 1. CONFIGURA O LAYOUT DINAMICAMENTE
 * Esta é a função mais importante. Ela recalcula tudo com base no tamanho da tela.
 */
function setupLayout() {
    const items = scrollContainer.querySelectorAll(".description");
    if (!items.length) return;

    // Pega os valores de estilo reais do container
    const styles = window.getComputedStyle(scrollContainer);
    const paddingLeft = parseFloat(styles.paddingLeft);
    const paddingRight = parseFloat(styles.paddingRight);
    const gap = parseFloat(styles.gap) || 16; // Pega o gap do CSS, ou usa 16 como padrão

    // Calcula a área REALMENTE disponível para os itens
    const availableWidth = scrollContainer.clientWidth - paddingLeft - paddingRight;

    // Pega a largura base de um item (do CSS) para saber quantos cabem
    const firstItemWidth = items[0].offsetWidth;

    // Calcula dinamicamente quantos itens cabem por página (p)
    const itemsPerPage = Math.floor((availableWidth + gap) / (firstItemWidth + gap));
    layoutConfig.itemsPerPage = itemsPerPage > 0 ? itemsPerPage : 1; // Garante pelo menos 1

    // Calcula a nova largura exata para os itens se encaixarem perfeitamente
    const totalGapSpace = (layoutConfig.itemsPerPage - 1) * gap;
    const newItemWidth = (availableWidth - totalGapSpace) / layoutConfig.itemsPerPage;

    // Aplica a nova largura e guarda os valores de configuração
    items.forEach(item => {
        item.style.flexBasis = `${newItemWidth}px`; // Usa flex-basis que é mais apropriado
        item.style.width = `${newItemWidth}px`;
    });
    
    layoutConfig.gap = gap;
    layoutConfig.totalPages = Math.ceil(items.length / layoutConfig.itemsPerPage);
    layoutConfig.pageWidth = (newItemWidth + gap) * layoutConfig.itemsPerPage;

    updatePageOnScroll(); // Atualiza a exibição da página
}

/**
 * 2. ATUALIZA O NÚMERO DA PÁGINA
 * Chamada durante a rolagem.
 */
function updatePageOnScroll() {
    if (!layoutConfig.pageWidth) return;

    // Calcula a página atual com base na posição da rolagem
    const currentPageIndex = Math.round(scrollContainer.scrollLeft / layoutConfig.pageWidth);
    const currentPage = currentPageIndex + 1;
    
    // Garante que o número da página não ultrapasse os limites
    const safePage = Math.max(1, Math.min(currentPage, layoutConfig.totalPages));
    pageDisplay.textContent = `${safePage}/${layoutConfig.totalPages}`;
}

/**
 * 3. EXECUTA A ROLAGEM (PARA OS BOTÕES)
 * @param {number} direction -1 para esquerda, 1 para direita
 */
function scrollByPage(direction) {
    if (!layoutConfig.pageWidth) return;

    scrollContainer.scrollBy({
        left: direction * layoutConfig.pageWidth,
        behavior: "smooth"
    });
}

// --- Event Listeners ---

// Usa um "debounce" para evitar cálculos excessivos durante a rolagem
scrollContainer.addEventListener("scroll", () => {
    clearTimeout(scrollTimeout);
    scrollTimeout = setTimeout(updatePageOnScroll, 150);
});

// Refaz todo o layout quando a janela é redimensionada ou carregada
window.addEventListener("resize", setupLayout);
window.addEventListener("load", setupLayout);

// Adiciona a funcionalidade aos botões de navegação
prevButton.addEventListener("click", () => scrollByPage(-1));
nextButton.addEventListener("click", () => scrollByPage(1));