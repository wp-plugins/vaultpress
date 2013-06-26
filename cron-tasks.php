<?php
include_once dirname( __FILE__ ) . '/vp-scanner.php';

class VP_Site_Scanner {
	function VP_Site_Scanner() {
		self::__construct();
	}
	function __construct() {
		add_action( 'vp_scan_site'      , array( $this, '_scan_site') );
		add_filter( 'cron_schedules'    , array( $this, '_custom_cron' ) );
		add_action( 'vp_scan_next_batch', array( $this, '_scan_batch' ) );

		$signatures = get_option( '_vp_signatures' );
		if ( $signatures && ! wp_next_scheduled( 'vp_scan_site' ) )
			wp_schedule_event( time(), 'daily', 'vp_scan_site' );
		if ( $signatures && ! wp_next_scheduled( 'vp_scan_next_batch' ) )
			wp_schedule_event( time(), 'five_minutes_interval', 'vp_scan_next_batch' );
	}

	function _custom_cron( $schedules ) {
		$schedules['five_minutes_interval'] = array(
			'interval' => 300,
			'display'  => __( 'Once every five minutes' ),
		);
		return $schedules;
	}

	function _scan_site() {
		if ( ! get_option( '_vp_current_scan' ) )
			update_option( '_vp_current_scan', new VP_FileScan( ABSPATH ) );
	}

	function _scan_batch() {
		$current = get_option( '_vp_current_scan' );
		if ( !is_object( $current ) )
			return;

		$default_batch_limit = 400;
		if ( function_exists( 'set_time_limit' ) )
			set_time_limit(0);
		else
			$default_batch_limit = 100; // avoid timeouts

		$limit = get_option( '_vp_batch_file_size', $default_batch_limit );
		$files = $current->get_files( $limit );
		$GLOBALS['vp_signatures'] = get_option( '_vp_signatures' );
		update_option( '_vp_current_scan', $current );

		if ( empty( $files ) && !$current->last_dir || empty( $GLOBALS['vp_signatures'] ) ) {
			delete_option('_vp_current_scan');
				return;
		}

		$results = array();
		foreach ( $files as $file ) {
			$verdict = vp_scan_file( $file );
			if ( !empty( $verdict ) )
				$results[$file] = @md5_file( $file );
		}

		if ( !empty( $results ) ) {
			$vaultpress = VaultPress::init();
			$vaultpress->add_ping( 'security', array( 'suspicious' => $results ) );
		}
	}

	function &init() {
		static $instance = false;
		if ( !$instance )
			$instance = new VP_Site_Scanner();
		return $instance;
	}
}
VP_Site_Scanner::init();
