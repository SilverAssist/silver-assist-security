<?php
/**
 * Render Helper class
 *
 * Provides reusable rendering utilities for dashboard UI components.
 * Ensures consistent HTML structure and CSS classes across all renderers.
 *
 * @package SilverAssist\Security\Admin\Renderer
 * @since   1.1.15
 */

namespace SilverAssist\Security\Admin\Renderer;

/**
 * Render Helper class
 *
 * @since 1.1.15
 */
class RenderHelper {

	/**
	 * Render a feature status row (enabled/disabled toggle display)
	 *
	 * @param string $label         The translatable feature name label.
	 * @param bool   $is_enabled    Whether the feature is enabled.
	 * @param string $enabled_text  Text to display when enabled. Default 'Enabled'.
	 * @param string $disabled_text Text to display when disabled. Default 'Disabled'.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public static function render_feature_status( string $label, bool $is_enabled, string $enabled_text = '', string $disabled_text = '' ): void {
		if ( '' === $enabled_text ) {
			$enabled_text = \esc_html__( 'Enabled', 'silver-assist-security' );
		}
		if ( '' === $disabled_text ) {
			$disabled_text = \esc_html__( 'Disabled', 'silver-assist-security' );
		}
		?>
		<div class="feature-status">
			<span class="feature-name"><?php echo \esc_html( $label ); ?></span>
			<span class="feature-value <?php echo $is_enabled ? 'enabled' : 'disabled'; ?>">
				<?php echo $is_enabled ? \esc_html( $enabled_text ) : \esc_html( $disabled_text ); ?>
			</span>
		</div>
		<?php
	}

	/**
	 * Render a stat value with label
	 *
	 * @param int|string $value  The stat value to display.
	 * @param string     $label  The translatable stat label.
	 * @param string     $suffix Optional suffix appended to the value (e.g., 's' for seconds).
	 * @param string     $id     Optional HTML id attribute for the stat-value element.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public static function render_stat( $value, string $label, string $suffix = '', string $id = '' ): void {
		?>
		<div class="stat">
			<span class="stat-value"<?php echo '' !== $id ? ' id="' . \esc_attr( $id ) . '"' : ''; ?>><?php echo (int) $value; ?><?php echo \esc_html( $suffix ); ?></span>
			<span class="stat-label"><?php echo \esc_html( $label ); ?></span>
		</div>
		<?php
	}

	/**
	 * Render an async stat card (loaded via AJAX with loading spinner)
	 *
	 * @param string $id    The HTML id for the stat-value element.
	 * @param string $label The translatable stat label.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public static function render_async_stat( string $id, string $label ): void {
		?>
		<div class="status-card">
			<div class="stat">
				<div class="stat-value" id="<?php echo \esc_attr( $id ); ?>">
					<span class="loading"></span>
				</div>
				<div class="stat-label"><?php echo \esc_html( $label ); ?></div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render a settings table row with a toggle switch (checkbox)
	 *
	 * @param string     $label       The row header label.
	 * @param string     $name        The input name and id attribute.
	 * @param int|bool   $checked     The current value (truthy = checked).
	 * @param string     $description The description text below the toggle.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public static function render_toggle_row( string $label, string $name, $checked, string $description ): void {
		?>
		<tr>
			<th scope="row">
				<?php echo \esc_html( $label ); ?>
			</th>
			<td>
				<label class="toggle-switch">
					<input type="checkbox"
							id="<?php echo \esc_attr( $name ); ?>"
							name="<?php echo \esc_attr( $name ); ?>"
							value="1"
							<?php \checked( $checked, 1 ); ?>>
					<span class="toggle-slider"></span>
				</label>
				<p class="description">
					<?php echo \esc_html( $description ); ?>
				</p>
			</td>
		</tr>
		<?php
	}

	/**
	 * Render a settings table row with a range slider
	 *
	 * @param string     $label           The row header label.
	 * @param string     $name            The input name and id attribute.
	 * @param int|string $value           The current input value.
	 * @param int        $min             Minimum range value.
	 * @param int        $max             Maximum range value.
	 * @param string     $slider_value_id The HTML id for the displayed slider value span.
	 * @param string     $display_value   The displayed value (may differ from $value, e.g. minutes conversion).
	 * @param string     $description     The description text below the slider.
	 * @param int        $step            The step increment. Default 1.
	 * @param int        $display_divisor Optional divisor for JS display conversion (e.g. 60 to convert seconds to minutes).
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public static function render_range_row( string $label, string $name, $value, int $min, int $max, string $slider_value_id, string $display_value, string $description, int $step = 1, int $display_divisor = 0 ): void {
		?>
		<tr>
			<th scope="row">
				<label for="<?php echo \esc_attr( $name ); ?>">
					<?php echo \esc_html( $label ); ?>
				</label>
			</th>
			<td>
				<input type="range"
						id="<?php echo \esc_attr( $name ); ?>"
						name="<?php echo \esc_attr( $name ); ?>"
						min="<?php echo \esc_attr( (string) $min ); ?>"
						max="<?php echo \esc_attr( (string) $max ); ?>"
						<?php echo 1 !== $step ? 'step="' . \esc_attr( (string) $step ) . '"' : ''; ?>
						<?php echo 0 !== $display_divisor ? 'data-display-divisor="' . \esc_attr( (string) $display_divisor ) . '"' : ''; ?>
						value="<?php echo \esc_attr( (string) $value ); ?>">
				<span class="slider-value" id="<?php echo \esc_attr( $slider_value_id ); ?>"><?php echo \esc_html( $display_value ); ?></span>
				<p class="description">
					<?php echo \esc_html( $description ); ?>
				</p>
			</td>
		</tr>
		<?php
	}
}
