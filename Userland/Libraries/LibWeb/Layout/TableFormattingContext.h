/*
 * Copyright (c) 2020, Andreas Kling <kling@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Forward.h>
#include <LibWeb/Layout/FormattingContext.h>
#include <LibWeb/Layout/TableWrapper.h>

namespace Web::Layout {

enum class TableDimension {
    Row,
    Column
};

class TableFormattingContext final : public FormattingContext {
public:
    explicit TableFormattingContext(LayoutState&, Box const&, FormattingContext* parent);
    ~TableFormattingContext();

    virtual void run(Box const&, LayoutMode, AvailableSpace const&) override;
    virtual CSSPixels automatic_content_width() const override;
    virtual CSSPixels automatic_content_height() const override;

    Box const& table_box() const { return context_box(); }
    TableWrapper const& table_wrapper() const
    {
        return verify_cast<TableWrapper>(*table_box().containing_block());
    }

private:
    CSSPixels run_caption_layout(LayoutMode, CSS::CaptionSide);
    CSSPixels compute_capmin();
    void calculate_row_column_grid(Box const&);
    void compute_cell_measures(AvailableSpace const& available_space);
    template<class RowOrColumn>
    void compute_table_measures();
    void compute_table_width();
    void distribute_width_to_columns();
    void compute_table_height(LayoutMode layout_mode);
    void distribute_height_to_rows();
    void position_row_boxes(CSSPixels&);
    void position_cell_boxes();
    void border_conflict_resolution();
    CSSPixels border_spacing_horizontal() const;
    CSSPixels border_spacing_vertical() const;

    CSSPixels m_table_height { 0 };
    CSSPixels m_automatic_content_height { 0 };

    Optional<AvailableSpace> m_available_space;

    enum class SizeType {
        Percent,
        Pixel,
        Auto
    };

    struct Column {
        SizeType type { SizeType::Auto };
        CSSPixels left_offset { 0 };
        CSSPixels min_size { 0 };
        CSSPixels max_size { 0 };
        CSSPixels used_width { 0 };
        double percentage_width { 0 };
    };

    struct Row {
        JS::NonnullGCPtr<Box const> box;
        CSSPixels base_height { 0 };
        CSSPixels reference_height { 0 };
        CSSPixels final_height { 0 };
        CSSPixels baseline { 0 };
        SizeType type { SizeType::Auto };
        CSSPixels min_size { 0 };
        CSSPixels max_size { 0 };
        double percentage_height { 0 };
    };

    struct Cell {
        JS::NonnullGCPtr<Box const> box;
        size_t column_index;
        size_t row_index;
        size_t column_span;
        size_t row_span;
        CSSPixels baseline { 0 };
        CSSPixels min_width { 0 };
        CSSPixels max_width { 0 };
        CSSPixels min_height { 0 };
        CSSPixels max_height { 0 };
    };

    // Accessors to enable direction-agnostic table measurement.

    template<class RowOrColumn>
    static size_t cell_span(Cell const& cell);

    template<class RowOrColumn>
    static size_t cell_index(Cell const& cell);

    template<class RowOrColumn>
    static CSSPixels cell_min_size(Cell const& cell);

    template<class RowOrColumn>
    static CSSPixels cell_max_size(Cell const& cell);

    template<class RowOrColumn>
    CSSPixels border_spacing();

    template<class RowOrColumn>
    Vector<RowOrColumn>& table_rows_or_columns();

    CSSPixels compute_row_content_height(Cell const& cell) const;

    enum class ConflictingEdge {
        Top,
        Right,
        Bottom,
        Left,
    };

    class BorderConflictFinder {
    public:
        BorderConflictFinder(TableFormattingContext const* context);
        Vector<Node const*> conflicting_elements(Cell const&, ConflictingEdge) const;

    private:
        void collect_conflicting_col_elements();

        Vector<Node const*> m_col_elements_by_index;
        TableFormattingContext const* m_context;
    };

    Vector<Cell> m_cells;
    Vector<Column> m_columns;
    Vector<Row> m_rows;
};

}
