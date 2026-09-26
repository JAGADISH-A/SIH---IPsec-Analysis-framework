import type { ButtonHTMLAttributes } from 'react'
import { cx } from '../../lib/cx'

export type ButtonVariant = 'default' | 'primary' | 'ghost' | 'danger'
export type ButtonSize = 'sm' | 'md' | 'icon' | 'icon-sm'

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  active?: boolean
}

const VARIANT: Record<ButtonVariant, string> = {
  default: '',
  primary: 'btn-primary',
  ghost: 'btn-ghost',
  danger: 'btn-danger',
}

const SIZE: Record<ButtonSize, string> = {
  sm: 'btn-sm',
  md: '',
  icon: 'btn-icon',
  'icon-sm': 'btn-icon btn-sm',
}

export function Button({ variant = 'default', size = 'md', active, className, ...rest }: ButtonProps) {
  return (
    <button
      type="button"
      className={cx('btn', VARIANT[variant], SIZE[size], active && 'btn-active', className)}
      {...rest}
    />
  )
}