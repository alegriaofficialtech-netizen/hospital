import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { MatChipsModule } from '@angular/material/chips';
import { ORDER_STATUS_LABELS, OrderStatus, orderStatusSlug } from '../core/models';

@Component({
  selector: 'app-order-status-badge',
  standalone: true,
  imports: [MatChipsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <mat-chip-set>
      <mat-chip [class]="chipClass()" disableRipple>{{ label() }}</mat-chip>
    </mat-chip-set>
  `,
  styles: [
    `
      :host {
        display: inline-block;
      }
      mat-chip-set {
        --mat-chip-container-height: 28px;
      }
    `,
  ],
})
export class OrderStatusBadgeComponent {
  readonly status = input.required<OrderStatus>();
  readonly label = computed(() => ORDER_STATUS_LABELS[this.status()]);
  readonly chipClass = computed(() => `status-badge status-${orderStatusSlug(this.status())}`);
}
