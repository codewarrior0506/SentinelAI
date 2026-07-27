document.addEventListener("DOMContentLoaded", function () {

    const pieCtx = document.getElementById("pieChart");

    if (pieCtx) {

        new Chart(pieCtx, {

            type: "pie",

            data: {

                labels: [
                    "Safe",
                    "Suspicious",
                    "Dangerous"
                ],

                datasets: [{

                    data: [
                        dashboardData.safe,
                        dashboardData.suspicious,
                        dashboardData.dangerous
                    ],

                    backgroundColor: [
                        "#10b981",
                        "#f59e0b",
                        "#ef4444"
                    ]

                }]

            }

        });

    }


    const barCtx = document.getElementById("barChart");

    if (barCtx) {

        new Chart(barCtx, {

            type: "bar",

            data: {

                labels: [
                    "Safe",
                    "Suspicious",
                    "Dangerous"
                ],

                datasets: [{

                    label: "URLs",

                    data: [
                        dashboardData.safe,
                        dashboardData.suspicious,
                        dashboardData.dangerous
                    ]

                }]

            },

            options: {

                responsive: true,

                plugins: {

                    legend: {

                        display: false

                    }

                }

            }

        });

    }

});

/* ---------- Animated Counters ---------- */

const counters = document.querySelectorAll(".counter");

counters.forEach(counter => {

    const target = Number(counter.dataset.target);

    let current = 0;

    const increment = target / 60;

    function updateCounter() {

        if (current < target) {

            current += increment;

            if (target % 1 === 0) {
                counter.textContent = Math.ceil(current);
            } else {
                counter.textContent = current.toFixed(1);
            }

            requestAnimationFrame(updateCounter);

        } else {

            if (target % 1 === 0) {
                counter.textContent = target;
            } else {
                counter.textContent = target.toFixed(2);
            }

        }

    }

    updateCounter();

});