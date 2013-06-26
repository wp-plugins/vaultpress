<?php

class VP_FileScan {
	var $path;
	var $last_dir = null;
	var $offset;

	function VP_FileScan($path) {
		if ( file_exists( $path ) )
			$this->last_dir = $this->path = @realpath( $path );
	}

	function get_files($limit = false) {
		static $dirs;
		if ( null == $dirs ) {
			$dirs = VP_FileScan::scan_dirs( $this->path );
			if ( is_dir( $this->path ) )
				array_unshift( $dirs, $this->path );
		}

		if ( empty( $this->last_dir ) )
			return array ();
		elseif ( is_file( $this->last_dir ) )
			return array ( $this->last_dir );

		$result = array ();
		$count = 0;
		$size = count( $dirs );
		$offset = $this->offset;

		for ( $i = array_search( $this->last_dir, $dirs ); false !== $i && $i < $size; $i++ ) {
			$path = $dirs[$i];
			$n = ( false !== $limit ) ? ( $limit - $count ) : false;
			$files = VP_FileScan::scan_files( $path, $n, $offset );
			$count += count( $files );
			$result = array_merge( $result, $files );

			if ( $limit && $count >= $limit ) {
				$this->offset += count( $files );
				$this->last_dir = $path;
				break;
			}
			$offset = 0;
		}
		if ( $i == $size )
			$this->last_dir = false;
		return $result;
	}

	static function scan_dirs($path) {
		if ( !is_dir( $path ) )
			return array ();

		$sub_dirs = VP_FileScan::scan_files( $path, false, 0, true );
		foreach ( $sub_dirs as $sub_dir )
			$sub_dirs = array_merge( $sub_dirs, VP_FileScan::scan_dirs( $sub_dir ) );
		return $sub_dirs;
	}

	static function scan_files($path, $limit = false, $offset = 0, $scan_dir = false) {
		$entries = array ();
		$ignore = $count = 0;
		if ( $handle = @opendir( $path ) ) {
			while ( false !== ( $entry = readdir( $handle ) ) ) {
				if ( $entry != "." && $entry != ".." ) {
					$entry = realpath( $path . DIRECTORY_SEPARATOR . $entry );
					if ( $scan_dir ) {
						if ( is_dir( $entry ) )
							$entries[] = $entry;
					} elseif ( is_file( $entry ) && vp_is_interesting_file( $entry ) ) {
						if ( $offset && ++$ignore <= $offset )
							continue;
						if ( false !== $limit && ++$count > $limit )
							break;
						$entries[] = realpath( $entry );
					}
				}
			}
			closedir( $handle );
		}
		return $entries;
	}
}

function vp_get_real_file_path( $file_path, $tmp_file = false ) {
	global $site, $site_id;
	$site_id = !empty( $site->id ) ? $site->id : $site_id;
	if ( !$tmp_file && !empty( $site_id ) && function_exists( 'determine_file_type_path' ) ) {
		$path = determine_file_type_path( $file_path );
		$file = file_by_path( $site_id, $path );
		if ( !$file )
			return false;
		return $file->get_unencrypted();
	}
	return !empty( $tmp_file ) ? $tmp_file : $file_path;
}

function vp_is_interesting_file($file) {
	$scan_only_regex = apply_filters( 'scan_only_extension_regex', '#\.(ph(p3|p4|p5|p|tml)|html|js|htaccess)$#i' );
	return preg_match( $scan_only_regex, $file );
}

/**
 * Scans a file with the registered signatures. To report a security notice for a specified signature, all its regular
 * expressions should result in a match.
 * @param $file the filename to be scanned.
 * @param null $tmp_file used if the file to be scanned doesn't exist or if the filename doesn't match vp_is_interesting_file().
 * @return array|bool false if no matched signature is found. A list of matched signatures otherwise.
 */
function vp_scan_file($file, $tmp_file = null) {
	$real_file = vp_get_real_file_path( $file, $tmp_file );
	$file_size = file_exists( $real_file ) ? @filesize( $real_file ) : 0;
	if ( !$file_size || $file_size > apply_filters( 'scan_max_file_size', 3 * 1024 * 1024 ) ) // don't scan empty or files larger than 3MB.
		return false;

	$file_content = null;
	$skip_file = apply_filters_ref_array( 'pre_scan_file', array ( false, $file, $real_file, &$file_content ) );
	if ( false !== $skip_file ) // maybe detect malware without regular expressions.
		return $skip_file;

	if ( !vp_is_interesting_file( $file ) ) // only scan relevant files.
		return false;

	$found = array ();
	foreach ( $GLOBALS['vp_signatures'] as $signature ) {
		// if there is no filename_regex, we assume it's the same of vp_is_interesting_file().
		if ( empty( $signature->filename_regex ) || preg_match( '#' . addcslashes( $signature->filename_regex, '#' ) . '#i', $file ) ) {
			if ( null === $file_content )
				$file_content = file_get_contents( $real_file );

			$is_vulnerable = true;
			reset( $signature->patterns );
			$matches = array ();
			while ( $is_vulnerable && list( , $pattern ) = each( $signature->patterns ) ) {
				if ( !preg_match( '#' . addcslashes( $pattern, '#' ) . '#im', $file_content, $match ) ) {
					$is_vulnerable = false;
					break;
				}
				$matches[] = $match;
			}
			// Additional checking needed?
			$is_vulnerable = apply_filters_ref_array( 'is_infected_by_' . $signature->name, array ( $is_vulnerable, $file, $real_file, &$file_content, &$matches ) );
			if ( $is_vulnerable ) {
				$found[$signature->id] = $matches;
				if ( isset( $signature->severity ) && $signature->severity > 8 ) // don't continue scanning
					break;
			}
		}
	}

	if ( empty( $found ) ) // only apply the filter when no signature is matched
		return apply_filters_ref_array( 'after_scan_file', array ( false, $file, $real_file, &$file_content ) );

	return $found;
}
