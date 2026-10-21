import { TestBed } from '@angular/core/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { provideRouter } from '@angular/router';
import { AuthService } from '../core/auth/auth.service';
import { ShellComponent } from './shell.component';

describe('ShellComponent', () => {
  beforeEach(async () => {
    sessionStorage.clear();
    await TestBed.configureTestingModule({
      imports: [ShellComponent],
      providers: [provideRouter([]), provideNoopAnimations()],
    }).compileComponents();
  });

  it('renders the app title and only the navigation allowed for the role', () => {
    const auth = TestBed.inject(AuthService);
    auth.loginDemo('ROLE_RECEPTION', 'demo.reception');

    const fixture = TestBed.createComponent(ShellComponent);
    fixture.detectChanges();
    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';

    expect(text).toContain('SGSI-ZTA Hospital Lab');
    expect(text).toContain('Admisión');
    expect(text).toContain('Indicadores');
    expect(text).not.toContain('Validación médica');
    expect(text).not.toContain('Auditoría');
  });
});
