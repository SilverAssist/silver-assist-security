<?php
/**
 * Silver Assist Security Essentials - Save Result
 *
 * What SettingsSaver::save() did with a submission, so the button path and the
 * auto-save endpoint can report it honestly.
 *
 * @package SilverAssist\Security\Admin\Settings
 * @since 1.5.4
 * @author Silver Assist
 */

namespace SilverAssist\Security\Admin\Settings;

/**
 * Save Result value class
 *
 * @since 1.5.4
 */
class SaveResult {

	/**
	 * Options written, keyed by option name, with the stored value
	 *
	 * @var array<string, mixed>
	 */
	public array $saved = array();

	/**
	 * Options whose stored value differs from the submitted one
	 *
	 * Keyed by option name: `submitted` is what the user sent, `saved` what was stored.
	 *
	 * @var array<string, array{submitted: mixed, saved: mixed}>
	 */
	public array $adjusted = array();

	/**
	 * Rejected submissions, keyed by option name or section, with a message
	 *
	 * @var array<string, string>
	 */
	public array $errors = array();

	/**
	 * Submitted keys the saver did not act on (unknown, other section, not eligible for auto-save)
	 *
	 * @var string[]
	 */
	public array $ignored = array();

	/**
	 * Number of options written
	 *
	 * @since 1.5.4
	 * @return int
	 */
	public function saved_count(): int {
		return count( $this->saved );
	}

	/**
	 * Result as a plain array (JSON responses, logs)
	 *
	 * @since 1.5.4
	 * @return array{saved_count: int, saved: array<string, mixed>, adjusted: array<string, array{submitted: mixed, saved: mixed}>, errors: array<string, string>, ignored: string[]}
	 */
	public function to_array(): array {
		return array(
			'saved_count' => $this->saved_count(),
			'saved'       => $this->saved,
			'adjusted'    => $this->adjusted,
			'errors'      => $this->errors,
			'ignored'     => $this->ignored,
		);
	}
}
