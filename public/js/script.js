const allSideMenu = document.querySelectorAll('#sidebar .side-menu.top li a');

allSideMenu.forEach(item=> {
	const li = item.parentElement;

	item.addEventListener('click', function () {
		allSideMenu.forEach(i=> {
			i.parentElement.classList.remove('active');
		})
		li.classList.add('active');
	})
});




// TOGGLE SIDEBAR
const menuBar = document.querySelector('#content nav .bx.bx-menu');
const sidebar = document.getElementById('sidebar');

menuBar.addEventListener('click', function () {
	sidebar.classList.toggle('hide');
})







const searchButton = document.querySelector('#content nav form .form-input button');
const searchButtonIcon = document.querySelector('#content nav form .form-input button .bx');
const searchForm = document.querySelector('#content nav form');

searchButton.addEventListener('click', function (e) {
	if(window.innerWidth < 576) {
		e.preventDefault();
		searchForm.classList.toggle('show');
		if(searchForm.classList.contains('show')) {
			searchButtonIcon.classList.replace('bx-search', 'bx-x');
		} else {
			searchButtonIcon.classList.replace('bx-x', 'bx-search');
		}
	}
})


async function downloadPDF() {
	const { jsPDF } = window.jspdf;
	const pdf = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });

	// Captura do gráfico de linha
	const canvas = document.getElementById('temperatureChart');
	const canvasImg = canvas.toDataURL('image/png');

	// Captura do heatmap (Plotly renderizado como div)
	const heatmapElement = document.getElementById('heatmap');
	const heatmapCanvas = await html2canvas(heatmapElement);
	const heatmapImg = heatmapCanvas.toDataURL('image/png');

	// Tamanho da página A4 útil
	const pageWidth = 190; // 210 - 2*10 mm margem
	const chartHeight = (canvas.height / canvas.width) * pageWidth;
	const heatmapHeight = (heatmapCanvas.height / heatmapCanvas.width) * pageWidth;

	// Adiciona os dois gráficos ao PDF
	pdf.addImage(canvasImg, 'PNG', 10, 10, pageWidth, chartHeight);
	pdf.addImage(heatmapImg, 'PNG', 10, 20 + chartHeight, pageWidth, heatmapHeight);

	// Salva o arquivo
	pdf.save('smai_dashboard.pdf');
}





if(window.innerWidth < 768) {
	sidebar.classList.add('hide');
} else if(window.innerWidth > 576) {
	searchButtonIcon.classList.replace('bx-x', 'bx-search');
	searchForm.classList.remove('show');
}


window.addEventListener('resize', function () {
	if(this.innerWidth > 576) {
		searchButtonIcon.classList.replace('bx-x', 'bx-search');
		searchForm.classList.remove('show');
	}
})



const switchMode = document.getElementById('switch-mode');

switchMode.addEventListener('change', function () {
	if(this.checked) {
		document.body.classList.add('dark');
	} else {
		document.body.classList.remove('dark');
	}
})

const ctx = document.getElementById('temperatureChart').getContext('2d');

const temperatureChart = new Chart(ctx, {
	type: 'line',
	data: {
		labels: ['22-03-2025', '01-04-2025', '15-05-2025', '04-05-2025', '10-07-2025'],
		datasets: [{
			label: 'Temperatura (°C)',
			data: [18, 40, 25, 36, 20],
			borderColor: '#00aaff',
			backgroundColor: 'rgba(0, 170, 255, 0.2)',
			tension: 0.3,
			fill: true,
			pointRadius: 5,
			pointHoverRadius: 7
		}]
	},
	options: {
		scales: {
			y: {
				beginAtZero: false
			}
		},
		plugins: {
			legend: {
				display: true,
				position: 'top'
			}
		},
		responsive: true
	}
});


const data = [{
  z: [
    [20, 22, 25, 28, 30],
    [19, 21, 24, 27, 29],
    [18, 20, 23, 26, 28],
    [17, 19, 22, 25, 27],
    [16, 18, 21, 24, 26]
  ],
  type: 'heatmap',
  colorscale: 'Jet', // azul → verde → amarelo → vermelho
  zsmooth: 'best',   // <<< Transição suave!
  showscale: true
}];

const layout = {
  title: 'Mapa de Calor Suavizado',
  xaxis: {
    title: 'Largura da Sala',
    showgrid: false
  },
  yaxis: {
    title: 'Profundidade da Sala',
    autorange: 'reversed',
    showgrid: false
  },
  margin: { t: 50 }
};

Plotly.newPlot('heatmap', data, layout);


