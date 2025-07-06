function entrar() {
    alert("botão funcionou")
}

const xValues = ["T", "U", "P"];
const yValues = [55, 49, 44, 24, 15];
const barColors = ["#ff869a", "#73b4ff","#2ed8b6"];

new Chart("chart1", {
  type: "bar",
  data: {
    labels: xValues,
    datasets: [{
      backgroundColor: barColors,
      data: yValues
    }]
  },
  options: {
    legend: {display: false},
    scales: {
      yAxes: [{
        ticks: {
          beginAtZero: true
        }
      }]
    },

    title: {
      display: true,
      text: "RX"
    }
  }
});