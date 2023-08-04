import Box from 'design/Box';
import { ButtonBorder } from 'design/Button';
import Flex from 'design/Flex';
import * as icons from 'design/Icon';
import React from 'react';
import Select from 'shared/components/Select';
import styled from 'styled-components';
import { encodeUrlQueryParams } from 'teleport/components/hooks/useUrlFiltering';
import { AgentFilter, SortType } from 'teleport/services/agents';

const kindOptions = [
  { label: 'Application', value: 'app' },
  { label: 'Database', value: 'db' },
  { label: 'Desktop', value: 'windows_desktop' },
  { label: 'Kubernetes', value: 'kube_cluster' },
  { label: 'Server', value: 'node' },
];

const sortFieldOptions = [
  { label: 'Name', value: 'name' },
  { label: 'Type', value: 'kind' },
];

export interface FilterPanelProps {
  pathname: string;
  replaceHistory: (path: string) => void;
  params: AgentFilter;
  setParams: (params: AgentFilter) => void;
  setSort: (sort: SortType) => void;
}

export function FilterPanel({
  pathname,
  replaceHistory,
  params,
  setParams,
  setSort,
}: FilterPanelProps) {
  const { sort, kinds } = params;
  const [sortMenuAnchor, setSortMenuAnchor] = React.useState(null);

  const activeSortFieldOption = sortFieldOptions.find(
    opt => opt.value === sort.fieldName
  );

  const activeKindOptions = kindOptions.filter(
    opt => kinds && kinds.includes(opt.value)
  );

  const onKindsChanged = (filter: any) => {
    setParams({ ...params, kinds: (filter ?? []).map(f => f.value) });
    // TODO(bl-nero): We really shouldn't have to do it, that's what setParams
    // should be for.
    const isAdvancedSearch = !!params.query;
    replaceHistory(
      encodeUrlQueryParams(
        pathname,
        params.search ?? params.query,
        params.sort,
        params.kinds,
        isAdvancedSearch
      )
    );
  };

  const onSortFieldChange = (option: any) => {
    setSort({ ...sort, fieldName: option.value });
  };

  const onSortMenuButtonClicked = event => {
    setSortMenuAnchor(event.currentTarget);
  };

  const onSortMenuClosed = () => {
    setSortMenuAnchor(null);
  };

  const onSortOrderButtonClicked = () => {
    setSort(oppositeSort(sort));
  };

  return (
    <Flex justifyContent="space-between" mb={2}>
      <Box width="300px">
        <Select
          isMulti={true}
          placeholder="Type"
          options={kindOptions}
          value={activeKindOptions}
          onChange={onKindsChanged}
        />
      </Box>
      <Flex>
        <Box width="100px">
          <SortSelect
            options={sortFieldOptions}
            value={activeSortFieldOption}
            onChange={onSortFieldChange}
          />
        </Box>
        <SortOrderButton px={3} onClick={onSortOrderButtonClicked}>
          {sort.dir === 'ASC' && <icons.SortAsc />}
          {sort.dir === 'DESC' && <icons.SortDesc />}
        </SortOrderButton>
      </Flex>
    </Flex>
  );
  return null;
}

function oppositeSort(sort: SortType): SortType {
  switch (sort.dir) {
    case 'ASC':
      return { ...sort, dir: 'DESC' };
    case 'DESC':
      return { ...sort, dir: 'ASC' };
    default:
      // Will never happen. Of course.
      return sort;
  }
}

const SortOrderButton = styled(ButtonBorder)`
  border-top-left-radius: 0;
  border-bottom-left-radius: 0;
`;

const SortSelect = styled(Select)`
  .react-select__control {
    border-right: none;
    border-top-right-radius: 0;
    border-bottom-right-radius: 0;
  }
  .react-select__dropdown-indicator {
    display: none;
  }
`;
