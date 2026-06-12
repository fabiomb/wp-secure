<?php
/**
 * Fixtures: Direcciones IP de prueba.
 */
return array(
	// IPv4 válidas.
	'valid_ipv4' => array(
		'192.168.1.1',
		'10.0.0.1',
		'172.16.0.1',
		'8.8.8.8',
		'1.1.1.1',
		'203.0.113.50',
		'198.51.100.25',
		'255.255.255.255',
		'0.0.0.0',
	),

	// IPv6 válidas.
	'valid_ipv6' => array(
		'::1',
		'2001:db8::1',
		'2001:0db8:85a3::8a2e:0370:7334',
		'fe80::1',
		'::ffff:192.168.1.1',
	),

	// IPs inválidas.
	'invalid' => array(
		'999.999.999.999',
		'abc.def.ghi.jkl',
		'192.168.1',
		'192.168.1.1.1',
		'',
		'not-an-ip',
		'12345',
		'192.168.1.256',
	),

	// IPs privadas/reservadas.
	'private' => array(
		'10.0.0.1',
		'10.255.255.255',
		'172.16.0.1',
		'172.31.255.255',
		'192.168.0.1',
		'192.168.255.255',
		'127.0.0.1',
		'::1',
		'169.254.1.1',   // Link-local.
	),

	// IPs públicas.
	'public' => array(
		'8.8.8.8',
		'1.1.1.1',
		'203.0.113.50',
		'198.51.100.25',
		'104.16.132.229',
		'2606:4700::6810:84e5',
	),

	// CIDRs de test.
	'cidrs' => array(
		'192.168.1.0/24'   => array( 'in' => '192.168.1.100', 'out' => '192.168.2.1' ),
		'10.0.0.0/8'       => array( 'in' => '10.255.255.255', 'out' => '11.0.0.1' ),
		'172.16.0.0/12'    => array( 'in' => '172.31.255.255', 'out' => '172.32.0.1' ),
		'203.0.113.0/28'   => array( 'in' => '203.0.113.15', 'out' => '203.0.113.16' ),
	),

	// Cloudflare IPs de test.
	'cloudflare' => array(
		'173.245.48.1',
		'104.16.1.1',
		'162.158.0.1',
	),

	// User-Agents de crawlers.
	'crawler_uas' => array(
		'googlebot'        => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
		'bingbot'          => 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
		'yandexbot'        => 'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
		'normal'           => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
		'facebookbot'      => 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
		// Navegador real de iOS/Safari que anexa tokens de bots sociales (falso positivo).
		'ios_safari_appended_bots' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/601.2.4 (KHTML, like Gecko) Version/9.0.1 Safari/601.2.4 facebookexternalhit/1.1 Facebot Twitterbot/1.0',
	),

	// User-Agents de scanners.
	'scanner_uas' => array(
		'WPScan v3.8.25',
		'Nikto/2.1.6',
		'sqlmap/1.7',
		'Mozilla/5.0 (compatible; Nessus)',
		'Acunetix Web Vulnerability Scanner',
	),
);
