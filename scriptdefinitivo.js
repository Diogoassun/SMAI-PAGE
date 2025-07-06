// --- Elementos do DOM ---
const scrollContainer = document.getElementById("func-scroll");
const pageDisplay = document.getElementById("pageDisplay");
const prevButton = document.getElementById("prevBtn"); // Adicione id="prev-btn" no seu HTML
const nextButton = document.getElementById("nextBtn"); // Adicione id="next-btn" no seu HTML

// --- Variáveis de Estado ---
let layoutConfig = {
    itemsPerPage: 0,
    totalPages: 0,
    pageWidth: 0,
};
let scrollTimeout;

/**
 * CONFIGURA O LAYOUT DINAMICAMENTE (Versão Corrigida)
 * Esta função agora apenas LÊ as dimensões, não as ALTERA.
 */
function setupLayout() {
    const items = Array.from(scrollContainer.querySelectorAll(".description"));
    if (!items.length) return;

    // --- 1. Descobrir as Dimensões ---
    const styles = window.getComputedStyle(scrollContainer);
    const gap = parseFloat(styles.gap) || 16;
    
    // Pega a largura de um item diretamente do DOM (definida pelo CSS)
    const itemWidth = items[0].offsetWidth;

    // Calcula a área útil dentro do container (descontando o padding da esquerda)
    const availableWidth = scrollContainer.clientWidth - parseFloat(styles.paddingLeft);

    // --- 2. Calcular Itens por Página e Páginas Totais ---
    // Calcula quantos itens com seus gaps cabem na área útil
    const itemsPerPage = Math.floor((availableWidth + gap) / (itemWidth + gap));
    layoutConfig.itemsPerPage = itemsPerPage > 0 ? itemsPerPage : 1;

    // Calcula o número total de páginas
    layoutConfig.totalPages = Math.ceil(items.length / layoutConfig.itemsPerPage);

    // --- 3. Calcular a Distância de Rolagem por Página ---
    // A distância a rolar é o tamanho de 'p' itens + seus gaps
    layoutConfig.pageWidth = layoutConfig.itemsPerPage * (itemWidth + gap);

    updatePageOnScroll(); // Atualiza o display inicial
}

/**
 * ATUALIZA O NÚMERO DA PÁGINA NA TELA (Versão Corrigida)
 */
function updatePageOnScroll() {
    if (!layoutConfig.pageWidth || layoutConfig.pageWidth === 0) return;

    // AQUI ESTÁ A CORREÇÃO: Trocar Math.round por Math.floor
    // Isso impede que a página seja arredondada para cima no final da rolagem.
    const currentPageIndex = Math.floor(scrollContainer.scrollLeft / layoutConfig.pageWidth);
    
    let currentPage = currentPageIndex + 1;
    
    // O clamping garante que o número final seja sempre válido.
    currentPage = Math.max(1, Math.min(currentPage, layoutConfig.totalPages));
    pageDisplay.textContent = `${currentPage}/${layoutConfig.totalPages}`;
}

/**
 * EXECUTA A ROLAGEM POR PÁGINA (Versão Mais Segura)
 * @param {number} direction -1 para esquerda, 1 para direita
 */
function scrollByPage(direction) {
    if (!layoutConfig.pageWidth || layoutConfig.pageWidth === 0) return;

    // Usa Math.floor para consistência com a função de display
    const currentPageIndex = Math.floor(scrollContainer.scrollLeft / layoutConfig.pageWidth);
    
    // Calcula o próximo índice da página
    let nextPageIndex = currentPageIndex + direction;

    // AQUI ESTÁ A MELHORIA:
    // Garante que o próximo índice não seja menor que 0 ou maior que a última página.
    nextPageIndex = Math.max(0, Math.min(nextPageIndex, layoutConfig.totalPages - 1));

    // Calcula a posição exata de rolagem para o índice alvo
    const targetScrollLeft = nextPageIndex * layoutConfig.pageWidth;

    scrollContainer.scrollTo({
        left: targetScrollLeft,
        behavior: "smooth"
    });
}

// --- Event Listeners ---

// "Debounce" para otimizar a performance durante a rolagem
scrollContainer.addEventListener("scroll", () => {
    clearTimeout(scrollTimeout);
    scrollTimeout = setTimeout(updatePageOnScroll, 150);
});

// Reconfigura o layout sempre que a página for carregada ou redimensionada
window.addEventListener("load", setupLayout);
window.addEventListener("resize", setupLayout);

// Ativa os botões de navegação
prevButton.addEventListener("click", () => scrollByPage(-1));
nextButton.addEventListener("click", () => scrollByPage(1));