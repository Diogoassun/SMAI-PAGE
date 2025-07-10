// Pegar referências dos selects
const selectMarca = document.getElementById('selectMarca');
const selectModelo = document.getElementById('selectModelo');

// Função para carregar marcas do backend
async function carregarMarcas() {
  try {
    const res = await fetch('/api/marcas');
    const marcas = await res.json();

    marcas.forEach(marca => {
      const option = document.createElement('option');
      option.value = marca.id;
      option.textContent = marca.nome;
      selectMarca.appendChild(option);
    });
  } catch (err) {
    console.error('Erro ao carregar marcas', err);
  }
}

// Função para carregar modelos baseado na marca selecionada
async function carregarModelos(marcaId) {
  selectModelo.innerHTML = '<option value="">Selecione o modelo</option>';
  if (!marcaId) {
    selectModelo.disabled = true;
    return;
  }
  try {
    const res = await fetch(`/api/modelos?marca_id=${marcaId}`);
    const modelos = await res.json();

    modelos.forEach(modelo => {
      const option = document.createElement('option');
      option.value = modelo.id;
      option.textContent = modelo.nome;
      selectModelo.appendChild(option);
    });

    selectModelo.disabled = false;
  } catch (err) {
    console.error('Erro ao carregar modelos', err);
  }
}

// Evento quando muda a marca selecionada
selectMarca.addEventListener('change', (e) => {
  carregarModelos(e.target.value);
});

// Chama a função para carregar as marcas assim que a página carregar
carregarMarcas();
