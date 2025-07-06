// Aguarda o evento 'load' da janela, que é disparado
// quando toda a página e seus recursos (imagens, css, etc.) foram carregados.
window.addEventListener('load', function() {
    const preloader = document.getElementById('preloader');
    
    // Adiciona a classe 'hidden' ao preloader,
    // o que ativará a transição de fade-out do CSS.
    preloader.classList.add('hidden');
});