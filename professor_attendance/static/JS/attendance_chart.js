document.addEventListener("DOMContentLoaded", function() {
    // Handle Chart.js setup
    const ctx = document.getElementById('attendanceChart').getContext('2d');
    const attendanceData = JSON.parse(document.getElementById('attendance-data').textContent);

    const labels = [];
    const onTimeData = [];
    const lateData = [];
    const absentData = [];
    const halfDayData = [];
    const overtimeData = [];

    for (let day = 1; day <= 31; day++) {
        labels.push(day);
        onTimeData.push(attendanceData[day]?.on_time || 0);
        lateData.push(attendanceData[day]?.late || 0);
        absentData.push(attendanceData[day]?.absent || 0);
        halfDayData.push(attendanceData[day]?.halfday || 0);
        overtimeData.push(attendanceData[day]?.overtime || 0);
    }

    const data = {
        labels: labels,
        datasets: [
            {
                label: 'On Time',
                data: onTimeData,
                backgroundColor: 'rgba(0, 255, 0, 0.6)',
                borderColor: 'green',
                borderWidth: 1,
            },
            {
                label: 'Late',
                data: lateData,
                backgroundColor: 'rgba(255, 165, 0, 0.6)',
                borderColor: 'orange',
                borderWidth: 1,
            },
            {
                label: 'Absent',
                data: absentData,
                backgroundColor: 'rgba(255, 0, 0, 0.6)',
                borderColor: 'red',
                borderWidth: 1,
            },
            {
                label: 'Half Day',
                data: halfDayData,
                backgroundColor: 'rgba(255, 255, 0, 0.6)',
                borderColor: 'yellow',
                borderWidth: 1,
            },
            {
                label: 'Overtime',
                data: overtimeData,
                backgroundColor: 'rgba(0, 0, 255, 0.6)',
                borderColor: 'blue',
                borderWidth: 1,
            }
        ]
    };

    const config = {
        type: 'bar',
        data: data,
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Days of the Month'
                    }
                },
                y: {
                    title: {
                        display: true,
                        text: 'Number of Records'
                    },
                    beginAtZero: true
                }
            }
        }
    };

    new Chart(ctx, config);

    // Export to PDF
    document.querySelector('.export-button').addEventListener('click', function () {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();

        // Get user's full name from a data attribute
        const userFullName = document.querySelector('.username').dataset.fullname;

        doc.text(`${userFullName}'s Attendance Record`, 10, 10);
        doc.addImage(ctx.canvas, 'PNG', 10, 20, 180, 150);
        doc.save(`${userFullName}_attendance_record.pdf`);
    });
});



document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll('.fill').forEach(el => {
      const width = el.getAttribute('data-width');
      el.style.width = width + '%';
    });
  });

  document.addEventListener("DOMContentLoaded", function () {
    const rawData = JSON.parse(document.getElementById("attendance-data-3months").textContent);

    const statuses = ['present', 'late', 'halfday', 'overtime', 'absent'];
    const statusColors = {
      present: '#4caf50',
      late: '#ff9800',
      halfday: '#03a9f4',
      overtime: '#9c27b0',
      absent: '#f44336'
    };

    const labels = Object.keys(rawData).reverse();  // Month labels
    const datasets = statuses.map(status => ({
      label: status.charAt(0).toUpperCase() + status.slice(1),
      data: labels.map(month => rawData[month][status]),
      backgroundColor: statusColors[status],
      stack: 'Attendance'
    }));

    new Chart(document.getElementById("monthlyAttendanceChart").getContext("2d"), {
      type: 'bar',
      data: {
        labels: labels,
        datasets: datasets
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position: 'top' },
          title: {
            display: false,
            text: 'Monthly Attendance by Status'
          }
        },
        scales: {
          x: { stacked: true },
          y: {
            stacked: true,
            beginAtZero: true,
            title: {
              display: true,
              text: 'Days'
            }
          }
        }
      }
    });
  });
