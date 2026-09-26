import type { HTMLAttributes, ReactNode, ThHTMLAttributes, TdHTMLAttributes } from 'react'
import { cx } from '../../lib/cx'

/* ------------------------------------------------------------------ */
/* Styled building blocks                                              */
/* ------------------------------------------------------------------ */

export function Table({ className, children, ...rest }: HTMLAttributes<HTMLTableElement>) {
  return (
    <div className="overflow-x-auto">
      <table className={cx('w-full border-collapse text-left text-[12px]', className)} {...rest}>
        {children}
      </table>
    </div>
  )
}

export function TableHead({ className, children, ...rest }: HTMLAttributes<HTMLTableSectionElement>) {
  return (
    <thead
      className={cx('border-b border-edge bg-night-900/60 text-[10px] uppercase tracking-wider text-mist-faint', className)}
      {...rest}
    >
      {children}
    </thead>
  )
}

export function TableBody({ className, children, ...rest }: HTMLAttributes<HTMLTableSectionElement>) {
  return (
    <tbody className={cx('divide-y divide-edge/60', className)} {...rest}>
      {children}
    </tbody>
  )
}

export interface TableRowProps extends HTMLAttributes<HTMLTableRowElement> {
  selected?: boolean
  interactive?: boolean
}

export function TableRow({ selected, interactive, className, ...rest }: TableRowProps) {
  return (
    <tr
      className={cx(
        'transition-colors',
        selected
          ? 'bg-accent-dim/40 hover:bg-accent-dim/50'
          : interactive
            ? 'cursor-pointer hover:bg-night-800/70'
            : 'hover:bg-night-800/30',
        className,
      )}
      {...rest}
    />
  )
}

export interface TableHeaderCellProps extends ThHTMLAttributes<HTMLTableCellElement> {
  align?: 'left' | 'right'
  width?: string
}

export function TableHeaderCell({ align = 'left', width, className, ...rest }: TableHeaderCellProps) {
  return (
    <th
      scope="col"
      className={cx(
        'px-3 py-2 font-semibold',
        align === 'right' && 'text-right',
        className,
      )}
      style={{ width }}
      {...rest}
    />
  )
}

export interface TableCellProps extends TdHTMLAttributes<HTMLTableCellElement> {
  align?: 'left' | 'right'
  nowrap?: boolean
}

export function TableCell({ align = 'left', nowrap, className, ...rest }: TableCellProps) {
  return (
    <td
      className={cx(
        'px-3 py-2 align-middle',
        align === 'right' && 'text-right',
        nowrap && 'whitespace-nowrap',
        className,
      )}
      {...rest}
    />
  )
}

export function TableEmpty({ colSpan, children }: { colSpan: number; children: ReactNode }) {
  return (
    <tr>
      <td colSpan={colSpan} className="px-3 py-12 text-center text-xs text-mist-faint">
        {children}
      </td>
    </tr>
  )
}

/* ------------------------------------------------------------------ */
/* Generic data table                                                  */
/* ------------------------------------------------------------------ */

export interface ColumnDef<T> {
  id: string
  header: ReactNode
  align?: 'left' | 'right'
  width?: string
  className?: string
  headerClassName?: string
  render: (row: T) => ReactNode
}

export interface DataTableProps<T> {
  columns: ColumnDef<T>[]
  rows: T[]
  rowKey: (row: T) => string
  selectedKey?: string
  onRowClick?: (row: T) => void
  empty?: ReactNode
}

/** Typed table rendering a column configuration over a row array. */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  selectedKey,
  onRowClick,
  empty,
}: DataTableProps<T>) {
  return (
    <Table>
      <TableHead>
        <tr>
          {columns.map((column) => (
            <TableHeaderCell
              key={column.id}
              align={column.align}
              width={column.width}
              className={column.headerClassName}
            >
              {column.header}
            </TableHeaderCell>
          ))}
        </tr>
      </TableHead>
      <TableBody>
        {rows.length === 0 ? (
          <TableEmpty colSpan={columns.length}>{empty ?? 'No rows to display.'}</TableEmpty>
        ) : (
          rows.map((row) => {
            const key = rowKey(row)
            return (
              <TableRow
                key={key}
                selected={key === selectedKey}
                interactive={Boolean(onRowClick)}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
              >
                {columns.map((column) => (
                  <TableCell
                    key={column.id}
                    align={column.align}
                    className={column.className}
                  >
                    {column.render(row)}
                  </TableCell>
                ))}
              </TableRow>
            )
          })
        )}
      </TableBody>
    </Table>
  )
}