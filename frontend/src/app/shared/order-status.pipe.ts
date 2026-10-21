import { Pipe, PipeTransform } from '@angular/core';
import { ORDER_STATUS_LABELS, OrderStatus } from '../core/models';

@Pipe({
  name: 'orderStatus',
  standalone: true,
})
export class OrderStatusPipe implements PipeTransform {
  transform(status: OrderStatus): string {
    return ORDER_STATUS_LABELS[status] ?? status;
  }
}
