/**
 * WP Seguro — JavaScript del panel de administración.
 */
(function ($) {
    'use strict';

    var WPS = {

        /** ID del último registro de tráfico recibido. */
        lastTrafficId: 0,

        /** Timer del polling de tráfico. */
        trafficTimer: null,

        /**
         * Inicialización.
         */
        init: function () {
            this.initSettingsNav();
            this.initConfirmActions();
            this.initToggleForms();
            this.initAjaxActions();
            this.initUnsafeMode();
            this.initUaToggle();
            this.initCustomRules();
            this.initExportImport();

            // Módulos por página.
            if (typeof wpsAdmin !== 'undefined') {
                if (wpsAdmin.page === 'wp-secure') {
                    this.initCharts();
                }
                if (wpsAdmin.page === 'wp-secure-traffic') {
                    this.initLiveTraffic();
                }
                if (wpsAdmin.page === 'index.php') {
                    this.initWidgetChart();
                }
            }
        },

        /*──────────────────────────────────────────
         * Chart.js — Dashboard
         *──────────────────────────────────────────*/

        initCharts: function () {
            if (typeof Chart === 'undefined' || typeof window.wpsChartData === 'undefined') {
                return;
            }

            var data = window.wpsChartData;

            // Gráfica de actividad 24h.
            var hourlyCtx = document.getElementById('wps-chart-hourly');
            if (hourlyCtx) {
                new Chart(hourlyCtx, {
                    type: 'line',
                    data: {
                        labels: data.hourly.labels,
                        datasets: [
                            {
                                label: 'Peticiones',
                                data: data.hourly.requests,
                                borderColor: '#2271b1',
                                backgroundColor: 'rgba(34,113,177,0.08)',
                                fill: true,
                                tension: 0.3,
                                pointRadius: 2
                            },
                            {
                                label: 'Bloqueadas',
                                data: data.hourly.blocks,
                                borderColor: '#d63638',
                                backgroundColor: 'rgba(214,54,56,0.08)',
                                fill: true,
                                tension: 0.3,
                                pointRadius: 2
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        interaction: { intersect: false, mode: 'index' },
                        scales: {
                            y: { beginAtZero: true, ticks: { precision: 0 } }
                        },
                        plugins: {
                            legend: { position: 'top' }
                        }
                    }
                });
            }

            // Gráfica de países.
            var countriesCtx = document.getElementById('wps-chart-countries');
            if (countriesCtx && data.countries.labels.length > 0) {
                new Chart(countriesCtx, {
                    type: 'bar',
                    data: {
                        labels: data.countries.labels,
                        datasets: [{
                            label: 'Peticiones',
                            data: data.countries.values,
                            backgroundColor: '#2271b1',
                            borderRadius: 3
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        indexAxis: 'y',
                        scales: {
                            x: { beginAtZero: true, ticks: { precision: 0 } }
                        },
                        plugins: {
                            legend: { display: false }
                        }
                    }
                });
            }
        },

        /*──────────────────────────────────────────
         * Chart.js — Dashboard Widget
         *──────────────────────────────────────────*/

        initWidgetChart: function () {
            if (typeof Chart === 'undefined' || typeof window.wpsWidgetChartData === 'undefined') {
                return;
            }

            var data = window.wpsWidgetChartData;
            var ctx = document.getElementById('wps-widget-chart-hourly');
            if (!ctx) {
                return;
            }

            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: data.labels,
                    datasets: [
                        {
                            label: 'Peticiones',
                            data: data.requests,
                            borderColor: '#2271b1',
                            backgroundColor: 'rgba(34,113,177,0.08)',
                            fill: true,
                            tension: 0.3,
                            pointRadius: 0,
                            borderWidth: 1.5
                        },
                        {
                            label: 'Bloqueadas',
                            data: data.blocks,
                            borderColor: '#d63638',
                            backgroundColor: 'rgba(214,54,56,0.08)',
                            fill: true,
                            tension: 0.3,
                            pointRadius: 0,
                            borderWidth: 1.5
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: { intersect: false, mode: 'index' },
                    scales: {
                        x: {
                            display: true,
                            ticks: { font: { size: 9 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 8 },
                            grid: { display: false }
                        },
                        y: {
                            beginAtZero: true,
                            ticks: { font: { size: 9 }, precision: 0 },
                            grid: { color: 'rgba(0,0,0,0.04)' }
                        }
                    },
                    plugins: {
                        legend: { position: 'bottom', labels: { font: { size: 10 }, boxWidth: 12, padding: 8 } }
                    }
                }
            });
        },

        /*──────────────────────────────────────────
         * Tráfico en Vivo
         *──────────────────────────────────────────*/

        initLiveTraffic: function () {
            var self = this;

            // Carga inicial.
            this.fetchTraffic();

            // Polling cada 5 segundos.
            this.trafficTimer = setInterval(function () {
                if (!$('#wps-traffic-pause').is(':checked')) {
                    self.fetchTraffic();
                }
            }, 5000);

            // Toggle pausa.
            $('#wps-traffic-pause').on('change', function () {
                var $status = $('#wps-traffic-status');
                if ($(this).is(':checked')) {
                    $status.removeClass('wps-badge-ok').addClass('wps-badge-warning').text(wpsAdmin.strings.paused);
                } else {
                    $status.removeClass('wps-badge-warning').addClass('wps-badge-ok').text(wpsAdmin.strings.live);
                    self.fetchTraffic();
                }
            });

            // Cambio de filtros → recarga inmediata.
            $('#wps-traffic-filters select').on('change', function () {
                self.lastTrafficId = 0;
                self.fetchTraffic();
            });

            var filterTimer = null;
            $('#wps-filter-ip').on('input', function () {
                clearTimeout(filterTimer);
                filterTimer = setTimeout(function () {
                    self.lastTrafficId = 0;
                    self.fetchTraffic();
                }, 400);
            });
        },

        fetchTraffic: function () {
            var self = this;
            var filters = {
                action: 'wps_get_live_traffic',
                nonce: wpsAdmin.nonce,
                visitor_type: $('#wps-filter-type').val(),
                method: $('#wps-filter-method').val(),
                ip: $('#wps-filter-ip').val()
            };

            // Solo pedir registros nuevos si ya tenemos datos.
            if (this.lastTrafficId > 0) {
                filters.since = this.lastTrafficId;
            }

            $.post(wpsAdmin.ajaxUrl, filters, function (response) {
                if (!response.success || !response.data.rows) {
                    return;
                }

                var rows = response.data.rows;
                if (rows.length === 0 && self.lastTrafficId > 0) {
                    return; // No hay nuevos registros.
                }

                var $tbody = $('#wps-traffic-body');

                // Si es la primera carga, limpiar.
                if (self.lastTrafficId === 0) {
                    $tbody.empty();
                }

                for (var i = rows.length - 1; i >= 0; i--) {
                    var r = rows[i];
                    var ipUrl = wpsAdmin.ajaxUrl.replace('admin-ajax.php', 'admin.php?page=wp-secure-traffic&ip=' + encodeURIComponent(r.ip_address));
                    var uaShort = r.user_agent ? r.user_agent.substring(0, 80) : '';
                    var uaNeedExpand = r.user_agent && r.user_agent.length > 80;
                    var uaHtml = '<span class="wps-ua-short">' + self.esc(uaShort) + (uaNeedExpand ? '…' : '') + '</span>';
                    if (uaNeedExpand) {
                        uaHtml += '<span class="wps-ua-full">' + self.esc(r.user_agent) + '</span>';
                        uaHtml += '<button type="button" class="wps-ua-toggle" data-collapsed="▼" data-expanded="▲">▼</button>';
                    }
                    var tr = '<tr class="wps-traffic-new">' +
                        '<td>' + self.esc(r.created_at) + '</td>' +
                        '<td><a href="' + ipUrl + '"><code>' + self.esc(r.ip_address) + '</code></a></td>' +
                        '<td>' + self.esc(r.country_code) + '</td>' +
                        '<td><span class="wps-badge wps-badge-info">' + self.esc(r.visitor_type) + '</span></td>' +
                        '<td><code>' + self.esc(r.request_method) + '</code></td>' +
                        '<td title="' + self.esc(r.request_uri) + '">' + self.esc(r.request_uri.substring(0, 80)) + '</td>' +
                        '<td>' + self.esc(r.http_status) + '</td>' +
                        '<td class="wps-ua-cell">' + uaHtml + '</td>' +
                        '<td>' +
                            '<a href="' + ipUrl + '" class="button button-small" title="Ver detalle"><span class="dashicons dashicons-visibility" style="font-size:14px;line-height:1.8;"></span></a> ' +
                            '<button type="button" class="button button-small wps-ajax-action" data-action="wps_block_ip" data-ip="' + self.esc(r.ip_address) + '" data-reason="Bloqueo manual desde tráfico en vivo" data-wps-confirm="¿Bloquear ' + self.esc(r.ip_address) + '?" title="Bloquear IP"><span class="dashicons dashicons-dismiss" style="font-size:14px;line-height:1.8;color:#d63638;"></span></button>' +
                        '</td>' +
                        '</tr>';
                    $tbody.prepend(tr);

                    if (r.id > self.lastTrafficId) {
                        self.lastTrafficId = r.id;
                    }
                }

                // Limitar a 100 filas visibles.
                $tbody.find('tr').slice(100).remove();

                // Quitar animación después de un momento.
                setTimeout(function () {
                    $tbody.find('.wps-traffic-new').removeClass('wps-traffic-new');
                }, 1500);

            }).fail(function () {
                // Silencioso — reintenta en el próximo ciclo.
            });
        },

        /*──────────────────────────────────────────
         * Acciones AJAX genéricas (botones con data-action)
         *──────────────────────────────────────────*/

        /*──────────────────────────────────────────
         * Modo Inseguro — toggle con un click
         *──────────────────────────────────────────*/

        initUnsafeMode: function () {
            $(document).on('click', '.wps-unsafe-toggle-btn', function (e) {
                e.preventDefault();
                var $btn = $(this);
                var nonce = $btn.data('nonce');
                if ($btn.prop('disabled')) return;

                $btn.prop('disabled', true).css('opacity', '0.6');

                $.post(wpsAdmin.ajaxUrl, {
                    action: 'wps_toggle_unsafe_mode',
                    nonce: nonce
                }, function (response) {
                    if (response.success) {
                        WPS.showNotice(response.data.message, 'success');
                        setTimeout(function () { location.reload(); }, 800);
                    } else {
                        var msg = (response.data && response.data.message) || wpsAdmin.strings.error;
                        WPS.showNotice(msg, 'error');
                        $btn.prop('disabled', false).css('opacity', '1');
                    }
                }).fail(function () {
                    WPS.showNotice(wpsAdmin.strings.error, 'error');
                    $btn.prop('disabled', false).css('opacity', '1');
                });
            });
        },

        initAjaxActions: function () {
            $(document).on('click', '.wps-ajax-action', function (e) {
                e.preventDefault();
                var $btn = $(this);
                if ($btn.prop('disabled')) return;

                var action = $btn.data('action');
                if (!action) return;

                // Construir datos desde data-* attributes.
                var postData = { action: action, nonce: wpsAdmin.nonce };
                var attrs = $btn.data();
                for (var key in attrs) {
                    if (key !== 'action' && attrs.hasOwnProperty(key)) {
                        postData[key] = attrs[key];
                    }
                }

                $btn.prop('disabled', true).css('opacity', '0.6');

                $.post(wpsAdmin.ajaxUrl, postData, function (response) {
                    if (response.success) {
                        var msg = response.data.message || wpsAdmin.strings.saved;
                        WPS.showNotice(msg, 'success');
                        // Recargar la página después de una acción exitosa.
                        setTimeout(function () { location.reload(); }, 1000);
                    } else {
                        var errMsg = (response.data && response.data.message) || wpsAdmin.strings.error;
                        WPS.showNotice(errMsg, 'error');
                        $btn.prop('disabled', false).css('opacity', '1');
                    }
                }).fail(function () {
                    WPS.showNotice(wpsAdmin.strings.error, 'error');
                    $btn.prop('disabled', false).css('opacity', '1');
                });
            });
        },

        /*──────────────────────────────────────────
         * User-Agent expand/collapse
         *──────────────────────────────────────────*/

        initUaToggle: function () {
            $(document).on('click', '.wps-ua-toggle', function (e) {
                e.preventDefault();
                var $cell = $(this).closest('.wps-ua-cell');
                $cell.toggleClass('wps-ua-expanded');
                var isExpanded = $cell.hasClass('wps-ua-expanded');
                $(this).text(isExpanded ? $(this).data('expanded') : $(this).data('collapsed'));
            });
        },

        /*──────────────────────────────────────────
         * Custom Rules — dynamic conditions
         *──────────────────────────────────────────*/

        initCustomRules: function () {
            var $container = $('#wps-conditions-container');
            if (!$container.length) {
                return;
            }

            // Add condition row.
            $('#wps-add-condition').on('click', function () {
                var index = $container.find('.wps-condition-row').length;
                var tmpl = $('#tmpl-wps-condition-row').html();
                if (!tmpl) return;
                tmpl = tmpl.replace(/\{\{data\.index\}\}/g, index);
                $container.append(tmpl);
            });

            // Remove condition row.
            $container.on('click', '.wps-remove-condition', function () {
                $(this).closest('.wps-condition-row').remove();
                // Reindex remaining rows.
                $container.find('.wps-condition-row').each(function (i) {
                    $(this).attr('data-index', i);
                    $(this).find('[name]').each(function () {
                        var name = $(this).attr('name');
                        $(this).attr('name', name.replace(/wps_conditions\[\d+\]/, 'wps_conditions[' + i + ']'));
                    });
                });
            });

            // Show/hide duration field based on action type.
            $('#wps-rule-action').on('change', function () {
                if ($(this).val() === 'block_temporary') {
                    $('#wps-duration-wrap').show();
                } else {
                    $('#wps-duration-wrap').hide();
                }
                if ($(this).val() === 'exempt') {
                    $('#wps-exempt-wrap').show();
                } else {
                    $('#wps-exempt-wrap').hide();
                }
            });

            // Show login_username hint when that field is selected in any condition.
            function checkLoginUsernameHint() {
                var hasLoginField = false;
                $container.find('.wps-condition-field').each(function () {
                    if ($(this).val() === 'login_username') {
                        hasLoginField = true;
                    }
                });
                $('.wps-login-username-hint').toggle(hasLoginField);
            }

            $container.on('change', '.wps-condition-field', checkLoginUsernameHint);
            $container.on('click', '.wps-remove-condition', function () {
                setTimeout(checkLoginUsernameHint, 50);
            });
            checkLoginUsernameHint();
        },

        /*──────────────────────────────────────────
         * Export / Import Configuración
         *──────────────────────────────────────────*/

        initExportImport: function () {
            // Botón de exportar configuración.
            $('#wps-export-config').on('click', function (e) {
                e.preventDefault();
                // Descargar vía form submission (AJAX con descarga de archivo).
                var url = wpsAdmin.ajaxUrl + '?action=wps_export_config&nonce=' + encodeURIComponent(wpsAdmin.nonce);
                window.location.href = url;
            });

            // Formulario de importar configuración.
            $('#wps-import-config-form').on('submit', function (e) {
                e.preventDefault();
                var $form = $(this);
                var $btn = $('#wps-import-config-btn');
                var fileInput = document.getElementById('wps-import-config-file');

                if (!fileInput || !fileInput.files.length) {
                    WPS.showNotice('Selecciona un archivo JSON.', 'error');
                    return;
                }

                if (!confirm(wpsAdmin.strings.confirm_import || '¿Importar esta configuración? Los ajustes actuales serán reemplazados.')) {
                    return;
                }

                $btn.prop('disabled', true).css('opacity', '0.6');

                var formData = new FormData();
                formData.append('action', 'wps_import_config');
                formData.append('nonce', wpsAdmin.nonce);
                formData.append('config_file', fileInput.files[0]);

                $.ajax({
                    url: wpsAdmin.ajaxUrl,
                    type: 'POST',
                    data: formData,
                    processData: false,
                    contentType: false,
                    success: function (response) {
                        if (response.success) {
                            WPS.showNotice(response.data.message, 'success');
                            setTimeout(function () { location.reload(); }, 2000);
                        } else {
                            var msg = (response.data && response.data.message) || 'Error al importar.';
                            WPS.showNotice(msg, 'error');
                            $btn.prop('disabled', false).css('opacity', '1');
                        }
                    },
                    error: function () {
                        WPS.showNotice('Error de conexión.', 'error');
                        $btn.prop('disabled', false).css('opacity', '1');
                    }
                });
            });
        },

        /*──────────────────────────────────────────
         * Utilidades
         *──────────────────────────────────────────*/

        /**
         * Mostrar notificación temporal.
         */
        showNotice: function (message, type) {
            var cls = type === 'error' ? 'notice-error' : 'notice-success';
            var $notice = $('<div class="notice ' + cls + ' is-dismissible" style="margin:8px 0;"><p>' + this.esc(message) + '</p></div>');
            $('.wps-wrap h1').first().after($notice);
            setTimeout(function () { $notice.fadeOut(300, function () { $(this).remove(); }); }, 4000);
        },

        /**
         * Escapar HTML básico.
         */
        esc: function (str) {
            if (!str) return '';
            var div = document.createElement('div');
            div.appendChild(document.createTextNode(str));
            return div.innerHTML;
        },

        /**
         * Navegación por secciones en la página de configuración.
         */
        initSettingsNav: function () {
            var $navItems = $('.wps-settings-nav-item');
            var $sections = $('.wps-settings-section');

            if (!$navItems.length || !$sections.length) {
                return;
            }

            // Activar la primera sección por defecto.
            $navItems.first().addClass('active');

            // Manejo de hash en URL.
            var hash = window.location.hash;
            if (hash && $(hash).length) {
                $navItems.removeClass('active');
                $navItems.filter('[href="' + hash + '"]').addClass('active');
            }

            // Click en navegación.
            $navItems.on('click', function (e) {
                e.preventDefault();
                var target = $(this).attr('href');

                $navItems.removeClass('active');
                $(this).addClass('active');

                // Scroll suave a la sección.
                if ($(target).length) {
                    $('html, body').animate({
                        scrollTop: $(target).offset().top - 50
                    }, 300);
                }

                // Actualizar hash sin saltar.
                if (window.history && window.history.replaceState) {
                    window.history.replaceState(null, null, target);
                }
            });
        },

        /**
         * Confirmación antes de acciones destructivas.
         */
        initConfirmActions: function () {
            $(document).on('click', '[data-wps-confirm]', function (e) {
                var message = $(this).data('wps-confirm') || wpsAdmin.strings.confirm_action;
                if (!confirm(message)) {
                    e.preventDefault();
                    return false;
                }
            });
        },

        /**
         * Toggle de formularios (agregar bloqueo, agregar whitelist).
         */
        initToggleForms: function () {
            $('#wps-toggle-add-block').on('click', function (e) {
                e.preventDefault();
                $('#wps-add-block-form').slideToggle(200);
            });

            $('#wps-toggle-add-whitelist').on('click', function (e) {
                e.preventDefault();
                $('#wps-add-whitelist-form').slideToggle(200);
            });

            $('#wps-toggle-add-rule').on('click', function (e) {
                e.preventDefault();
                $('#wps-custom-rule-form').slideToggle(200);
            });
        }
    };

    // Inicializar cuando el DOM esté listo.
    $(document).ready(function () {
        WPS.init();
    });

})(jQuery);
