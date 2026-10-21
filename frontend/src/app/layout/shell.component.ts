import { BreakpointObserver } from '@angular/cdk/layout';
import { ChangeDetectionStrategy, Component, computed, effect, inject, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatButtonModule } from '@angular/material/button';
import { MatChipsModule } from '@angular/material/chips';
import { MatIconModule } from '@angular/material/icon';
import { MatListModule } from '@angular/material/list';
import { MatSidenavModule } from '@angular/material/sidenav';
import { MatToolbarModule } from '@angular/material/toolbar';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { map } from 'rxjs/operators';
import { ROLE_LABELS, UserRole } from '../core/models';
import { AuthService } from '../core/auth/auth.service';

interface NavItem {
  label: string;
  icon: string;
  route: string;
  roles: readonly UserRole[];
}

const NAV_ITEMS: readonly NavItem[] = [
  {
    label: 'Dashboard',
    icon: 'dashboard',
    route: '/dashboard',
    roles: [
      'ROLE_RECEPTION',
      'ROLE_LAB_TECH',
      'ROLE_PATHOLOGIST',
      'ROLE_SECURITY_AUDITOR',
    ],
  },
  { label: 'Admission', icon: 'assignment_ind', route: '/admision', roles: ['ROLE_RECEPTION'] },
  {
    label: 'Medical validation',
    icon: 'biotech',
    route: '/medico',
    roles: ['ROLE_PATHOLOGIST'],
  },
  {
    label: 'Audit trail',
    icon: 'verified_user',
    route: '/auditoria',
    roles: ['ROLE_SECURITY_AUDITOR'],
  },
  {
    label: 'Indicators',
    icon: 'monitoring',
    route: '/indicadores',
    roles: [
      'ROLE_RECEPTION',
      'ROLE_LAB_TECH',
      'ROLE_PATHOLOGIST',
      'ROLE_SECURITY_AUDITOR',
    ],
  },
];

@Component({
  selector: 'app-shell',
  standalone: true,
  imports: [
    MatButtonModule,
    MatChipsModule,
    MatIconModule,
    MatListModule,
    MatSidenavModule,
    MatToolbarModule,
    RouterLink,
    RouterLinkActive,
    RouterOutlet,
  ],
  templateUrl: './shell.component.html',
  styleUrl: './shell.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ShellComponent {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly breakpoint = inject(BreakpointObserver);

  readonly user = this.auth.user;
  readonly navItems = computed(() => NAV_ITEMS.filter((item) => this.auth.hasAnyRole(item.roles)));
  readonly roleLabel = computed(() => {
    const first = this.auth.roles()[0];
    return first ? ROLE_LABELS[first] : 'No role';
  });
  readonly initials = computed(() => {
    const name = this.auth.user()?.displayName ?? 'User';
    return name
      .split(/\s+/)
      .slice(0, 2)
      .map((part) => part.charAt(0).toUpperCase())
      .join('');
  });
  readonly isMobile = toSignal(
    this.breakpoint.observe('(max-width: 900px)').pipe(map((state) => state.matches)),
    { initialValue: false },
  );
  readonly sidenavOpen = signal(true);

  constructor() {
    effect(() => {
      this.sidenavOpen.set(!this.isMobile());
    });
  }

  onNavigate(): void {
    if (this.isMobile()) {
      this.sidenavOpen.set(false);
    }
  }

  async logout(): Promise<void> {
    await this.auth.logout();
    await this.router.navigate(['/login']);
  }
}
