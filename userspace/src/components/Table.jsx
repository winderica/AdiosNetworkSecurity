import {
    AddBox,
    ArrowDownward,
    Check,
    ChevronLeft,
    ChevronRight,
    Clear,
    DeleteOutline,
    Edit,
    FilterList,
    FirstPage,
    LastPage,
    Remove,
    SaveAlt,
    Search,
    ViewColumn
} from '@material-ui/icons';
import MaterialTable from 'material-table';
import { observer } from 'mobx-react';
import React, { forwardRef } from 'react';

const forwardSVGRef = (Icon) => {
    return forwardRef((props, ref) => <Icon {...props} ref={ref} />);
};

export const Table = observer(({ title, data, columns, editable, actions }) => {
    return (
        <MaterialTable
            title={title}
            data={data}
            columns={columns}
            editable={editable}
            actions={actions}
            icons={{
                Add: forwardSVGRef(AddBox),
                Check: forwardSVGRef(Check),
                Clear: forwardSVGRef(Clear),
                Delete: forwardSVGRef(DeleteOutline),
                DetailPanel: forwardSVGRef(ChevronRight),
                Edit: forwardSVGRef(Edit),
                Export: forwardSVGRef(SaveAlt),
                Filter: forwardSVGRef(FilterList),
                FirstPage: forwardSVGRef(FirstPage),
                LastPage: forwardSVGRef(LastPage),
                NextPage: forwardSVGRef(ChevronRight),
                PreviousPage: forwardSVGRef(ChevronLeft),
                ResetSearch: forwardSVGRef(Clear),
                Search: forwardSVGRef(Search),
                SortArrow: forwardSVGRef(ArrowDownward),
                ThirdStateCheck: forwardSVGRef(Remove),
                ViewColumn: forwardSVGRef(ViewColumn)
            }}
            options={{
                search: false,
                headerStyle: {
                    padding: 16,
                    whiteSpace: 'nowrap'
                },
                grouping: false
            }}
            // localization={{
            //     header: {
            //         actions: '动作'
            //     },
            //     grouping: {
            //         placeholder: '将标签列标题拖拽至此以进行分组',
            //         groupedBy: '分组：'
            //     },
            //     body: {
            //         emptyDataSourceMessage: '暂无数据',
            //         editRow: {
            //             saveTooltip: '保存',
            //             cancelTooltip: '取消',
            //             deleteText: '确定删除？',
            //         },
            //         addTooltip: '添加',
            //         deleteTooltip: '删除',
            //         editTooltip: '编辑',
            //     },
            //     pagination: {
            //         firstTooltip: '第一页',
            //         previousTooltip: '前一页',
            //         nextTooltip: '下一页',
            //         labelDisplayedRows: '{from}到{to}行 共{count}行',
            //         lastTooltip: '最后一页',
            //         labelRowsSelect: '行每页',
            //     }
            // }}
        />
    );
});
