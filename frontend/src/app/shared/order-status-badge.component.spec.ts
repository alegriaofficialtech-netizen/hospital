import { TestBed } from '@angular/core/testing';
import { ORDER_STATUSES, ORDER_STATUS_LABELS } from '../core/models';
import { OrderStatusBadgeComponent } from './order-status-badge.component';

describe('OrderStatusBadgeComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [OrderStatusBadgeComponent],
    }).compileComponents();
  });

  it('renders a human label and a status class for every status', () => {
    for (const status of ORDER_STATUSES) {
      const fixture = TestBed.createComponent(OrderStatusBadgeComponent);
      fixture.componentRef.setInput('status', status);
      fixture.detectChanges();

      const element = fixture.nativeElement as HTMLElement;
      const chip = element.querySelector('mat-chip');

      expect(element.textContent).toContain(ORDER_STATUS_LABELS[status]);
      expect(chip?.className).toContain(
        `status-${status.toLowerCase().replace(/_/g, '-')}`,
      );

      fixture.destroy();
    }
  });
});
