package eastguard.dashboard;

import java.util.List;
import java.util.function.BiFunction;
import javax.swing.table.AbstractTableModel;

/** A read-only Swing table model over a list of rows. Changed on the EDT only. */
final class RowTableModel<T> extends AbstractTableModel {
    private static final long serialVersionUID = 1L;
    private final String[] columns;
    private final transient BiFunction<T, Integer, Object> cell;
    private transient List<T> rows = List.of();

    RowTableModel(String[] columns, BiFunction<T, Integer, Object> cell) {
        this.columns = columns.clone();
        this.cell = cell;
    }

    void setRows(List<T> rows) {
        this.rows = List.copyOf(rows);
        fireTableDataChanged();
    }

    T row(int i) {
        return i < 0 || i >= rows.size() ? null : rows.get(i);
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return columns.length;
    }

    @Override
    public String getColumnName(int c) {
        return columns[c];
    }

    @Override
    public Object getValueAt(int r, int c) {
        return cell.apply(rows.get(r), c);
    }
}
