<?php
/**
 * Silver Assist Security Essentials - Save Result
 *
 * What SettingsSaver did with a submission, so the settings screen can report it
 * honestly, per option, next to the field.
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
	 * What was submitted for an option that was rejected, keyed by option name
	 *
	 * The form shows it again next to the error, so the user does not retype it.
	 *
	 * @var array<string, string>
	 */
	public array $submitted = array();

	/**
	 * Submitted keys the saver did not act on (unknown, other section)
	 *
	 * @var string[]
	 */
	public array $ignored = array();

	/**
	 * URL the admin is reachable at when Admin Hide is on after the save, empty otherwise
	 *
	 * @var string
	 */
	public string $admin_url = '';

	/**
	 * Whether the Admin Hide section changed state and the rewrite rules were flushed
	 *
	 * @var bool
	 */
	public bool $rewrite_flushed = false;

	/**
	 * Merge the result of another section into this one
	 *
	 * @since 1.5.4
	 * @param SaveResult $other Result to merge.
	 * @return void
	 */
	public function merge( SaveResult $other ): void {
		$this->saved           = array_merge( $this->saved, $other->saved );
		$this->adjusted        = array_merge( $this->adjusted, $other->adjusted );
		$this->errors          = array_merge( $this->errors, $other->errors );
		$this->submitted       = array_merge( $this->submitted, $other->submitted );
		$this->ignored         = array_values( array_unique( array_merge( $this->ignored, $other->ignored ) ) );
		$this->admin_url       = '' !== $other->admin_url ? $other->admin_url : $this->admin_url;
		$this->rewrite_flushed = $this->rewrite_flushed || $other->rewrite_flushed;
	}

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
